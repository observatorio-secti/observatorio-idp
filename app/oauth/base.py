from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field


class OAuthUserInfo(BaseModel):
    provider: str
    provider_user_id: str
    email: str | None = None
    name: str | None = None
    email_verified: bool = False
    raw_data: dict[str, Any] = Field(default_factory=dict)


class BaseOAuthProvider(ABC):
    name: str

    @abstractmethod
    def get_authorization_url(self, state: str) -> str:
        """Gera a URL de consentimento para redirecionar o usuário."""

    @abstractmethod
    async def get_user_info(self, code: str) -> OAuthUserInfo:
        """Troca o authorization code pelo access token e retorna os dados unificados do usuário."""
