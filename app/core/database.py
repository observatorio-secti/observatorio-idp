from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

connect_args = {}
if settings.DATABASE_URL.startswith('sqlite'):
    connect_args['check_same_thread'] = False

engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

async_session_maker = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependência FastAPI que fornece uma sessão assíncrona do SQLAlchemy."""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()
