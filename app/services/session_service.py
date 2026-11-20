from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Request, Response
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_token
from app.models.token import IdpSession, RefreshToken
from app.models.user import User
from app.services.token_service import ensure_utc


def is_https_request(request: Request) -> bool:
    """Identifica se a requisição original chegou por HTTPS (direto ou via proxy)."""
    forwarded_proto = (
        request.headers.get('x-forwarded-proto', '')
        .split(',')[0]
        .strip()
        .lower()
    )
    return request.url.scheme == 'https' or forwarded_proto == 'https'


def set_session_cookie(
    response: Response, request: Request, raw_token: str
) -> None:
    """Grava o cookie HttpOnly da sessão SSO do IdP na resposta HTTP."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.SESSION_EXPIRE_DAYS * 86400,
        path='/',
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        secure=is_https_request(request),
    )


def clear_session_cookie(response: Response, request: Request) -> None:
    """Remove o cookie da sessão SSO do IdP na resposta HTTP."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path='/',
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        secure=is_https_request(request),
    )


class SessionService:
    @staticmethod
    async def create_session(session: AsyncSession, user_id: UUID) -> str:
        """Cria e persiste uma nova sessão de navegador para o usuário no IdP."""
        raw_token = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        idp_session = IdpSession(
            user_id=user_id,
            token_hash=hash_token(raw_token),
            expires_at=now + timedelta(days=settings.SESSION_EXPIRE_DAYS),
        )
        session.add(idp_session)
        await session.commit()
        return raw_token

    @staticmethod
    async def get_active_user_from_cookie(
        session: AsyncSession, raw_token: str | None
    ) -> User | None:
        """Valida o token de sessão do cookie e retorna o usuário ativo, se válido."""
        if not raw_token:
            return None

        token_hash = hash_token(raw_token)
        stmt = select(IdpSession).where(IdpSession.token_hash == token_hash)
        idp_session = await session.scalar(stmt)
        if not idp_session or idp_session.revoked_at is not None:
            return None

        now = datetime.now(timezone.utc)
        if ensure_utc(idp_session.expires_at) < now:
            return None

        user = await session.get(User, idp_session.user_id)
        if not user or not user.is_active:
            return None

        return user

    @staticmethod
    async def revoke_session(
        session: AsyncSession,
        raw_token: str | None,
        revoke_refresh_tokens: bool = True,
        client_id: str | None = None,
    ) -> None:
        """Revoga a sessão do IdP e, opcionalmente, os refresh tokens ativos do usuário."""
        if not raw_token:
            return

        token_hash = hash_token(raw_token)
        stmt = select(IdpSession).where(IdpSession.token_hash == token_hash)
        idp_session = await session.scalar(stmt)
        if not idp_session:
            return

        now = datetime.now(timezone.utc)
        if idp_session.revoked_at is None:
            idp_session.revoked_at = now

        if revoke_refresh_tokens:
            refresh_stmt = (
                update(RefreshToken)
                .where(
                    RefreshToken.user_id == idp_session.user_id,
                    RefreshToken.revoked_at.is_(None),
                )
                .values(revoked_at=now)
            )
            if client_id:
                refresh_stmt = refresh_stmt.where(
                    RefreshToken.client_id == client_id
                )
            await session.execute(refresh_stmt)

        await session.commit()
