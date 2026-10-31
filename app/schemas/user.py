from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr


class IdentityPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    provider: str
    provider_user_id: str
    email: str | None = None
    created_at: datetime


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    name: str
    is_active: bool
    role: str = 'DEFAULT'
    has_password: bool
    created_at: datetime
    identities: list[IdentityPublic] = []
