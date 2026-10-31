from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.core.database import get_session
from app.core.keys import create_access_token
from app.core.security import get_password_hash
from app.main import app
from app.models.base import Base
from tests.factories import ApplicationFactory, IdentityFactory, UserFactory


@pytest_asyncio.fixture
async def async_engine():
    """Engine assíncrono em memória compartilhado por StaticPool."""
    engine = create_async_engine(
        'sqlite+aiosqlite:///:memory:',
        connect_args={'check_same_thread': False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def session(async_engine) -> AsyncGenerator[AsyncSession, None]:
    """Sessão assíncrona isolada para testes."""
    session_maker = async_sessionmaker(
        bind=async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_maker() as session:
        yield session


@pytest.fixture
def client(session: AsyncSession):
    """TestClient do FastAPI com override da dependência de sessão."""

    async def get_session_override():
        yield session

    app.dependency_overrides[get_session] = get_session_override
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def user_generator(session: AsyncSession):
    """Fixture geradora assíncrona para persistir usuários nos testes."""

    async def _generate_user(**kwargs: Any):
        raw_password = kwargs.pop('password', 'testpassword123')
        password_hash = (
            get_password_hash(raw_password)
            if raw_password is not None
            else None
        )
        user = UserFactory(password_hash=password_hash, **kwargs)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        user.raw_password = raw_password
        return user

    return _generate_user


@pytest_asyncio.fixture
async def user(user_generator):
    """Usuário padrão de teste persistido no banco."""
    return await user_generator()


@pytest.fixture
def auth_headers(user):
    """Gera cabeçalho HTTP de autorização Bearer RS256 para o usuário padrão."""
    token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        name=user.name,
    )
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def app_generator(session: AsyncSession):
    """Fixture geradora assíncrona para persistir aplicações clientes OAuth nos testes."""

    async def _generate_app(**kwargs: Any):
        application = ApplicationFactory(**kwargs)
        session.add(application)
        await session.commit()
        await session.refresh(application)
        return application

    return _generate_app


@pytest_asyncio.fixture
async def application(app_generator):
    """Aplicação cliente OAuth padrão persistida no banco."""
    return await app_generator()


@pytest.fixture
def identity_generator(session: AsyncSession):
    """Fixture geradora para persistir identidades vinculadas a usuários."""

    async def _generate_identity(user, **kwargs: Any):
        identity = IdentityFactory(user_id=user.id, **kwargs)
        session.add(identity)
        await session.commit()
        await session.refresh(identity)
        return identity

    return _generate_identity
