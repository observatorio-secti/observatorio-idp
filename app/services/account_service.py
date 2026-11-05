from __future__ import annotations

from http import HTTPStatus
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.models.identity import Identity
from app.models.user import User
from app.oauth.base import OAuthUserInfo
from app.schemas.auth import LoginRequest, RegisterRequest

# Hash fictício pré-calculado com Argon2 para mitigar timing attacks quando usuário não existe
DUMMY_ARGON2_HASH = get_password_hash(
    'dummy_timing_attack_protection_password'
)


class AccountService:
    @staticmethod
    async def get_by_email(session: AsyncSession, email: str) -> User | None:
        """Busca usuário por e-mail com suas identidades carregadas."""
        stmt = (
            select(User)
            .options(selectinload(User.identities))
            .where(User.email == email.lower().strip())
        )
        return await session.scalar(stmt)

    @staticmethod
    async def get_by_id(session: AsyncSession, user_id: UUID) -> User | None:
        """Busca usuário por ID com suas identidades carregadas."""
        stmt = (
            select(User)
            .options(selectinload(User.identities))
            .where(User.id == user_id)
        )
        return await session.scalar(stmt)

    @classmethod
    async def register_local_user(
        cls, session: AsyncSession, data: RegisterRequest
    ) -> User:
        """Registra um novo usuário com autenticação local (Argon2)."""
        clean_email = data.email.lower().strip()
        existing = await cls.get_by_email(session, clean_email)
        if existing:
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail='E-mail já cadastrado no sistema.',
            )

        role = (
            'ADMIN'
            if clean_email == settings.ADMIN_EMAIL.lower().strip()
            else 'DEFAULT'
        )
        user = User(
            email=clean_email,
            name=data.name.strip(),
            password_hash=get_password_hash(data.password),
            is_active=True,
            role=role,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    @classmethod
    async def authenticate_local_user(
        cls, session: AsyncSession, data: LoginRequest
    ) -> User:
        """Autentica o usuário com e-mail e senha, com proteção contra enumeração e timing attacks."""
        clean_email = data.email.lower().strip()
        user = await cls.get_by_email(session, clean_email)

        if not user:
            # Executa verificação simulada para equalizar o tempo de resposta
            verify_password(data.password, DUMMY_ARGON2_HASH)
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail='Credenciais inválidas.',
            )

        if user.password_hash is None:
            # Conta criada via login social sem senha local definida
            verify_password(data.password, DUMMY_ARGON2_HASH)
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail='Esta conta foi criada através de login social. Utilize o provedor correspondente.',
            )

        if not verify_password(data.password, user.password_hash):
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail='Credenciais inválidas.',
            )

        if not user.is_active:
            raise HTTPException(
                status_code=HTTPStatus.FORBIDDEN,
                detail='Conta inativa. Entre em contato com o suporte.',
            )

        return user

    @classmethod
    async def link_identity(
        cls,
        session: AsyncSession,
        user: User,
        provider: str,
        provider_user_id: str,
        email: str | None = None,
    ) -> Identity:
        """Vincula uma nova identidade externa à conta do usuário logado."""
        # Verifica se já está vinculada a alguém
        stmt = select(Identity).where(
            Identity.provider == provider,
            Identity.provider_user_id == str(provider_user_id),
        )
        existing = await session.scalar(stmt)
        if existing:
            if existing.user_id == user.id:
                return existing
            raise HTTPException(
                status_code=HTTPStatus.CONFLICT,
                detail=f'Esta conta {provider} já está associada a outro usuário.',
            )

        identity = Identity(
            user_id=user.id,
            provider=provider,
            provider_user_id=str(provider_user_id),
            email=email.lower().strip() if email else None,
        )
        session.add(identity)
        await session.commit()
        await session.refresh(identity)
        return identity

    @classmethod
    async def unlink_identity(
        cls, session: AsyncSession, user: User, provider: str
    ) -> None:
        """Remove a vinculação com um provedor externo, impedindo desvinculação se for o único método de login."""
        identities_stmt = select(Identity).where(Identity.user_id == user.id)
        identities = (await session.scalars(identities_stmt)).all()

        target_identity = next(
            (i for i in identities if i.provider == provider), None
        )
        if not target_identity:
            raise HTTPException(
                status_code=HTTPStatus.NOT_FOUND,
                detail=f"Nenhuma identidade do provedor '{provider}' vinculada a esta conta.",
            )

        # Regra de proteção: usuário sem senha local não pode remover sua única identidade social restante
        has_local_password = user.password_hash is not None
        if not has_local_password and len(identities) <= 1:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='Não é possível remover a identidade. Este é o único método de autenticação da sua conta.',
            )

        await session.delete(target_identity)
        await session.commit()
        await session.refresh(user, attribute_names=['identities'])

    @classmethod
    async def authenticate_or_link_federated_user(
        cls, session: AsyncSession, user_info: OAuthUserInfo
    ) -> User:
        """Autentica ou vincula o usuário federado conforme as regras estritas de segurança.

        - Identidade já existente: autentica diretamente o usuário.
        - E-mail existente + email_verified=True (Google): vincula automaticamente.
        - E-mail existente + email_verified=False (ORCID): recusa vinculação automática (anti-sequestro).
        - Novo usuário: cria conta sem senha com a identidade vinculada.
        """
        # 1. Verifica se a identidade (provider, provider_user_id) já existe
        stmt = (
            select(User)
            .join(Identity)
            .where(
                Identity.provider == user_info.provider,
                Identity.provider_user_id == str(user_info.provider_user_id),
            )
            .options(selectinload(User.identities))
        )
        existing_user = await session.scalar(stmt)
        if existing_user:
            if not existing_user.is_active:
                raise HTTPException(
                    status_code=HTTPStatus.FORBIDDEN,
                    detail='Conta de usuário inativa.',
                )
            return existing_user

        # 2. Se não encontrou a identidade, verifica se o e-mail já pertence a uma conta existente
        clean_email = (
            user_info.email.lower().strip() if user_info.email else None
        )
        if clean_email:
            existing_by_email = await cls.get_by_email(session, clean_email)
            if existing_by_email:
                # Regra estrita de verificação de e-mail (anti-sequestro)
                if user_info.email_verified:
                    # Provedor garante que o e-mail é legítimo (ex.: Google)
                    identity = Identity(
                        user_id=existing_by_email.id,
                        provider=user_info.provider,
                        provider_user_id=str(user_info.provider_user_id),
                        email=clean_email,
                    )
                    session.add(identity)
                    await session.commit()
                    await session.refresh(existing_by_email)
                    return existing_by_email
                else:
                    # Provedor NÃO garante verificação (ex.: ORCID) -> Recusa vínculo automático
                    raise HTTPException(
                        status_code=HTTPStatus.CONFLICT,
                        detail=(
                            f"O e-mail '{clean_email}' já está cadastrado em outra conta. "
                            f'Como o {user_info.provider.upper()} não garante a verificação do e-mail, '
                            'o vínculo automático foi bloqueado por segurança. '
                            'Por favor, efetue login na sua conta existente e vincule o provedor pelo perfil (/me).'
                        ),
                    )

        # 3. Criação de nova conta para usuário que não existe
        if clean_email:
            account_email = clean_email
            account_name = user_info.name or clean_email.split('@')[0]
        else:
            # Usuário sem e-mail público (ex.: ORCID)
            account_email = f'orcid_{user_info.provider_user_id}@orcid.org'
            account_name = (
                user_info.name
                or f'Pesquisador ORCID {user_info.provider_user_id}'
            )

        role = (
            'ADMIN'
            if clean_email
            and clean_email == settings.ADMIN_EMAIL.lower().strip()
            else 'DEFAULT'
        )
        new_user = User(
            email=account_email,
            name=account_name,
            password_hash=None,  # Conta puramente federada
            is_active=True,
            role=role,
        )
        session.add(new_user)
        await session.flush()

        identity = Identity(
            user_id=new_user.id,
            provider=user_info.provider,
            provider_user_id=str(user_info.provider_user_id),
            email=clean_email,
        )
        session.add(identity)
        await session.commit()
        await session.refresh(new_user)
        return new_user

    @classmethod
    async def seed_admin_user(cls, session: AsyncSession) -> User | None:
        """Cadastra o usuário administrador padrão caso ainda não exista no banco."""
        clean_email = settings.ADMIN_EMAIL.lower().strip()
        if not clean_email or not settings.ADMIN_PASSWORD:
            return None

        existing = await cls.get_by_email(session, clean_email)
        if existing:
            return existing

        user = User(
            email=clean_email,
            name=settings.ADMIN_NAME.strip(),
            password_hash=get_password_hash(settings.ADMIN_PASSWORD),
            is_active=True,
            role='ADMIN',
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user
