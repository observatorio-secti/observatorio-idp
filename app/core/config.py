from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
        extra='ignore',
    )

    # Ambiente e Servidor
    ENVIRONMENT: str = 'development'
    PROJECT_NAME: str = 'observatorio-idp'
    IDP_ISSUER: str = 'http://localhost:8000'

    # Banco de Dados
    DATABASE_URL: str = Field(
        default='sqlite+aiosqlite:///./observatorio_idp.db',
        description='URL de conexão assíncrona do banco de dados (SQLite ou PostgreSQL)',
    )

    # Chaves Criptográficas e JWT
    # Se IDP_PRIVATE_KEY_PEM estiver vazio, uma chave RSA de 2048 bits será gerada dinamicamente
    IDP_PRIVATE_KEY_PEM: str = ''
    IDP_KEY_ID: str = 'default-kid'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    AUTHORIZATION_CODE_EXPIRE_MINUTES: int = 5

    # Redirecionamento Padrão de Frontend
    FRONTEND_AUTH_CALLBACK_URL: str = 'http://localhost:3000/auth/callback'

    # Provedor Google OAuth
    GOOGLE_CLIENT_ID: str = ''
    GOOGLE_CLIENT_SECRET: str = ''
    GOOGLE_REDIRECT_URI: str = 'http://localhost:8000/auth/google/callback'

    # Provedor ORCID OAuth
    ORCID_CLIENT_ID: str = ''
    ORCID_CLIENT_SECRET: str = ''
    ORCID_REDIRECT_URI: str = 'http://localhost:8000/auth/orcid/callback'
    ORCID_SANDBOX: bool = True

    # Administrador Inicial (Bootstrap)
    ADMIN_EMAIL: str = 'admin@observatorio.ba.gov.br'
    ADMIN_NAME: str = 'Administrador Observatório'
    ADMIN_PASSWORD: str = 'admin_secret_password'


settings = Settings()
