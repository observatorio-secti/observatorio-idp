from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.identity import Identity
    from app.models.token import AuthorizationCode, RefreshToken


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = 'users'

    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    role: Mapped[str] = mapped_column(
        String(50), default='DEFAULT', server_default='DEFAULT', nullable=False
    )

    identities: Mapped[list[Identity]] = relationship(
        'Identity',
        back_populates='user',
        cascade='all, delete-orphan',
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        'RefreshToken',
        back_populates='user',
        cascade='all, delete-orphan',
    )
    authorization_codes: Mapped[list[AuthorizationCode]] = relationship(
        'AuthorizationCode',
        back_populates='user',
        cascade='all, delete-orphan',
    )
