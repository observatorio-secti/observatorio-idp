import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import async_session_maker
from app.routers import auth, authorize, jwks, me, oauth_providers
from app.services.application_service import ApplicationService

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    async with async_session_maker() as session:
        try:
            await ApplicationService.seed_default_applications(session)
            logger.info('Aplicações padrão semeadas com sucesso.')
        except Exception as e:
            logger.warning(
                'Não foi possível semear as aplicações padrão no startup: %s', e
            )
    yield


app = FastAPI(
    title='Observatório IdP',
    description='Serviço central de identidade e servidor OAuth2 do ecossistema Observatório.',
    version='0.1.0',
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(jwks.router)
app.include_router(auth.router)
app.include_router(authorize.router)
app.include_router(oauth_providers.router)
app.include_router(me.router)


@app.get('/health', tags=['health'])
async def health_check() -> dict[str, str]:
    """Endpoint de checagem de integridade do serviço."""
    return {'status': 'ok', 'service': settings.PROJECT_NAME}
