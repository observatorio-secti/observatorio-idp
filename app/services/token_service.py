from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from uuid import UUID, uuid4

from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.keys import create_access_token
from app.core.security import hash_token
from app.models.token import AuthorizationCode, RefreshToken
from app.models.user import User
from app.schemas.oauth import OAuthTokenResponse


def ensure_utc(dt: datetime) -> datetime:
    """Garante que o datetime possua fuso horário UTC (especialmente importante para SQLite)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def validate_pkce(
    code_verifier: str, code_challenge: str, method: str
) -> bool:
    """Valida o code_verifier contra o code_challenge conforme RFC 7636."""
    if method == 'plain':
        return secrets.compare_digest(code_verifier, code_challenge)

    if method == 'S256':
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        calculated = (
            base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
        )
        return secrets.compare_digest(calculated, code_challenge)

    return False


class TokenService:
    @staticmethod
    async def create_authorization_code(
        session: AsyncSession,
        client_id: str,
        user_id: UUID,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = 'S256',
    ) -> str:
        """Gera e armazena um Authorization Code com validade de 5 minutos."""
        if code_challenge_method not in {'S256', 'plain'}:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="invalid_request: code_challenge_method deve ser 'S256' ou 'plain'.",
            )

        raw_code = secrets.token_urlsafe(32)
        code_hash = hash_token(raw_code)
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(
            minutes=settings.AUTHORIZATION_CODE_EXPIRE_MINUTES
        )

        auth_code = AuthorizationCode(
            code_hash=code_hash,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            expires_at=expires_at,
        )
        session.add(auth_code)
        await session.commit()
        return raw_code

    @classmethod
    async def exchange_authorization_code(
        cls,
        session: AsyncSession,
        client_id: str,
        raw_code: str,
        redirect_uri: str,
        code_verifier: str,
    ) -> OAuthTokenResponse:
        """Troca o authorization code pelo access token e refresh token com validação PKCE."""
        code_hash = hash_token(raw_code)
        stmt = select(AuthorizationCode).where(
            AuthorizationCode.code_hash == code_hash
        )
        auth_code = await session.scalar(stmt)

        if not auth_code:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Código de autorização inválido.',
            )

        now = datetime.now(timezone.utc)

        if auth_code.used_at is not None:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Código de autorização já utilizado.',
            )

        if ensure_utc(auth_code.expires_at) < now:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Código de autorização expirado.',
            )

        if auth_code.client_id != client_id:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Código não pertence a esta aplicação cliente.',
            )

        if auth_code.redirect_uri != redirect_uri:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: redirect_uri não coincide com a autorizada.',
            )

        if not validate_pkce(
            code_verifier,
            auth_code.code_challenge,
            auth_code.code_challenge_method,
        ):
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Falha na validação PKCE (code_verifier inválido).',
            )

        # Marca código como usado (uso único)
        auth_code.used_at = now

        # Carrega usuário
        user = await session.get(User, auth_code.user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Usuário inativo ou inexistente.',
            )

        # Emite access token JWT RS256
        access_token = create_access_token(
            user_id=str(user.id),
            email=user.email,
            name=user.name,
            role=user.role,
            client_id=client_id,
        )

        # Emite refresh token opaco com nova família
        raw_refresh = secrets.token_urlsafe(32)
        refresh_hash = hash_token(raw_refresh)
        family_id = uuid4()
        refresh_token = RefreshToken(
            user_id=user.id,
            client_id=client_id,
            token_hash=refresh_hash,
            family_id=family_id,
            expires_at=now
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        session.add(refresh_token)
        await session.commit()

        return OAuthTokenResponse(
            access_token=access_token,
            token_type='bearer',
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_token=raw_refresh,
        )

    @classmethod
    async def rotate_refresh_token(
        cls,
        session: AsyncSession,
        client_id: str,
        raw_refresh_token: str,
    ) -> OAuthTokenResponse:
        """Rotaciona o refresh token com detecção de reúso e revogação em cascata da família."""
        token_hash = hash_token(raw_refresh_token)
        stmt = select(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        )
        token = await session.scalar(stmt)

        now = datetime.now(timezone.utc)

        if not token:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Refresh token inválido.',
            )

        # Detecção de reúso: se o token já foi utilizado, revoga toda a família
        if token.used_at is not None:
            await session.execute(
                update(RefreshToken)
                .where(RefreshToken.family_id == token.family_id)
                .values(revoked_at=now)
            )
            await session.commit()
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Tentativa de reúso de refresh token detectada. Toda a cadeia de renovação foi revogada por segurança.',
            )

        if token.revoked_at is not None:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Refresh token revogado.',
            )

        if ensure_utc(token.expires_at) < now:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Refresh token expirado.',
            )

        if token.client_id != client_id:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Refresh token não pertence a esta aplicação cliente.',
            )

        # Marca token atual como usado
        token.used_at = now

        user = await session.get(User, token.user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_grant: Usuário inativo ou inexistente.',
            )

        # Emite novo access token
        access_token = create_access_token(
            user_id=str(user.id),
            email=user.email,
            name=user.name,
            role=user.role,
            client_id=client_id,
        )

        # Gera novo refresh token mantendo o mesmo family_id
        new_raw_refresh = secrets.token_urlsafe(32)
        new_refresh_hash = hash_token(new_raw_refresh)
        new_refresh_token = RefreshToken(
            user_id=user.id,
            client_id=client_id,
            token_hash=new_refresh_hash,
            family_id=token.family_id,
            expires_at=now
            + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        )
        session.add(new_refresh_token)
        await session.commit()

        return OAuthTokenResponse(
            access_token=access_token,
            token_type='bearer',
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            refresh_token=new_raw_refresh,
        )
