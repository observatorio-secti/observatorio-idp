from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import ExpiredSignatureError, InvalidTokenError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.keys import key_manager
from app.models.user import User
from app.services.account_service import AccountService

bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials, Depends(bearer_scheme)
    ],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> User:
    """Extrai e valida o token JWT RS256 do cabeçalho de autorização e carrega o usuário."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail='Token de acesso inválido ou expirado.',
        headers={'WWW-Authenticate': 'Bearer'},
    )

    try:
        payload = key_manager.decode_jwt(credentials.credentials)
        sub = payload.get('sub')
        if not sub:
            raise credentials_exception
        user_id = UUID(sub)
    except (ExpiredSignatureError, InvalidTokenError, ValueError) as err:
        raise credentials_exception from err

    user = await AccountService.get_by_id(session, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Usuário inativo ou não encontrado.',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
DbSession = Annotated[AsyncSession, Depends(get_session)]
