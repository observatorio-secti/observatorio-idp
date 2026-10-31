from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.token import AuthorizationCode, RefreshToken


class Application(Base):
    __tablename__ = 'applications'

    client_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    client_secret: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    redirect_uris: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        'RefreshToken',
        back_populates='application',
        cascade='all, delete-orphan',
    )
    authorization_codes: Mapped[list[AuthorizationCode]] = relationship(
        'AuthorizationCode',
        back_populates='application',
        cascade='all, delete-orphan',
    )
