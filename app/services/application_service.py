from __future__ import annotations

from http import HTTPStatus

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.application import Application


class ApplicationService:
    @staticmethod
    async def get_application(
        session: AsyncSession, client_id: str
    ) -> Application | None:
        """Busca uma aplicação cliente por client_id."""
        stmt = select(Application).where(Application.client_id == client_id)
        return await session.scalar(stmt)

    @classmethod
    async def validate_client_and_redirect(
        cls, session: AsyncSession, client_id: str, redirect_uri: str
    ) -> Application:
        """Valida se a aplicação cliente existe, está ativa e se a redirect_uri é autorizada.

        Em caso de erro na redirect_uri, a requisição DEVE ser rejeitada sem redirecionamento
        (RFC 6749, Seção 3.1.2).
        """
        app = await cls.get_application(session, client_id)
        if not app or not app.is_active:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_client: Aplicação cliente não encontrada ou inativa.',
            )

        if redirect_uri not in app.redirect_uris:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail='invalid_request: redirect_uri não autorizada para esta aplicação.',
            )

        return app

    @classmethod
    async def register_application(
        cls,
        session: AsyncSession,
        client_id: str,
        name: str,
        redirect_uris: list[str],
        client_secret: str | None = None,
    ) -> Application:
        """Registra ou atualiza uma aplicação cliente no IdP."""
        app = await cls.get_application(session, client_id)
        if app:
            app.name = name
            app.redirect_uris = redirect_uris
            app.client_secret = client_secret
            app.is_active = True
        else:
            app = Application(
                client_id=client_id,
                name=name,
                client_secret=client_secret,
                redirect_uris=redirect_uris,
                is_active=True,
            )
            session.add(app)

        await session.commit()
        await session.refresh(app)
        return app

    @classmethod
    async def seed_default_applications(cls, session: AsyncSession) -> None:
        """Cadastra as aplicações padrão do ecossistema Observatório caso não existam."""
        default_apps = [
            {
                'client_id': 'simcc',
                'name': 'Simcc Plataforma',
                'redirect_uris': [
                    'http://localhost:3000/auth/callback',
                    'http://localhost:8000/auth/callback',
                    'http://localhost:8080/auth/callback',
                    'http://localhost:8080/simcc/auth/callback',
                    'http://localhost:5173/auth/callback',
                    'http://localhost:5173/simcc/auth/callback',
                    'http://127.0.0.1:8080/auth/callback',
                    'http://127.0.0.1:8080/simcc/auth/callback',
                    'http://127.0.0.1:5173/auth/callback',
                    'https://observatoriocti.secti.ba.gov.br/simcc/auth/callback',
                    'https://observatoriocti.secti.ba.gov.br/auth/callback',
                ],
            },
            {
                'client_id': 'observatorio',
                'name': 'Observatório Portal',
                'redirect_uris': [
                    'http://localhost:3000/auth/callback',
                    'http://localhost:3001/auth/callback',
                    'http://localhost:5173/auth/callback',
                    'http://localhost:5173/',
                    'http://localhost:5174/auth/callback',
                    'http://localhost:5174/',
                    'http://127.0.0.1:5173/auth/callback',
                    'http://127.0.0.1:5173/',
                    'http://127.0.0.1:5174/auth/callback',
                    'https://observatoriocti.secti.ba.gov.br/auth/callback',
                    'https://observatoriocti.secti.ba.gov.br/',
                ],
            },
        ]
        for app_data in default_apps:
            existing = await cls.get_application(
                session, app_data['client_id']
            )
            if not existing:
                app = Application(
                    client_id=app_data['client_id'],
                    name=app_data['name'],
                    redirect_uris=app_data['redirect_uris'],
                    is_active=True,
                )
                session.add(app)
            else:
                # Garante que novas URIs sejam adicionadas
                current_uris = set(existing.redirect_uris)
                for u in app_data['redirect_uris']:
                    current_uris.add(u)
                existing.redirect_uris = list(current_uris)
        await session.commit()
