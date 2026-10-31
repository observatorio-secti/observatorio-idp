from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.application import Application
    from app.models.user import User


class RefreshToken(Base, UUIDPrimaryKeyMixin):
    __tablename__ = 'refresh_tokens'

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    client_id: Mapped[str] = mapped_column(
        ForeignKey('applications.client_id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=False,
    )
    family_id: Mapped[UUID] = mapped_column(nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user: Mapped[User] = relationship('User', back_populates='refresh_tokens')
    application: Mapped[Application] = relationship(
        'Application', back_populates='refresh_tokens'
    )


class AuthorizationCode(Base):
    __tablename__ = 'authorization_codes'

    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(
        ForeignKey('applications.client_id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey('users.id', ondelete='CASCADE'),
        nullable=False,
        index=True,
    )
    redirect_uri: Mapped[str] = mapped_column(String(2048), nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    code_challenge_method: Mapped[str] = mapped_column(
        String(10), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    user: Mapped[User] = relationship(
        'User', back_populates='authorization_codes'
    )
    application: Mapped[Application] = relationship(
        'Application', back_populates='authorization_codes'
    )
