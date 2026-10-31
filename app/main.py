from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.routers import auth, authorize, jwks, me, oauth_providers

app = FastAPI(
    title='Observatório IdP',
    description='Serviço central de identidade e servidor OAuth2 do ecossistema Observatório.',
    version='0.1.0',
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
