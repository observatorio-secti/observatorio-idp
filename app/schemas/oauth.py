from typing import Literal

from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    grant_type: Literal['authorization_code', 'refresh_token']
    client_id: str
    client_secret: str | None = None
    # Campos para authorization_code
    code: str | None = None
    redirect_uri: str | None = None
    code_verifier: str | None = None
    # Campo para refresh_token
    refresh_token: str | None = None


class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = 'bearer'
    expires_in: int = 900
    refresh_token: str
    scope: str = 'openid profile email'


class ApplicationCreate(BaseModel):
    client_id: str
    name: str
    client_secret: str | None = None
    redirect_uris: list[str] = Field(default_factory=list)
