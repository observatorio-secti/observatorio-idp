from http import HTTPStatus

from fastapi import APIRouter, Response

from app.core.dependencies import DbSession
from app.core.keys import create_access_token
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse
from app.schemas.user import UserPublic
from app.services.account_service import AccountService

router = APIRouter(prefix='/auth', tags=['auth'])


@router.post(
    '/register',
    response_model=UserPublic,
    status_code=HTTPStatus.CREATED,
)
async def register(
    data: RegisterRequest,
    session: DbSession,
) -> UserPublic:
    """Registra um novo usuário com autenticação local."""
    user = await AccountService.register_local_user(session, data)
    return UserPublic(
        id=user.id,
        email=user.email,
        name=user.name,
        is_active=user.is_active,
        role=user.role,
        has_password=True,
        created_at=user.created_at,
        identities=[],
    )


@router.post(
    '/login',
    response_model=TokenResponse,
    status_code=HTTPStatus.OK,
)
async def login(
    data: LoginRequest,
    session: DbSession,
) -> TokenResponse:
    """Autentica o usuário com e-mail e senha e emite um access token JWT RS256."""
    user = await AccountService.authenticate_local_user(session, data)
    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        name=user.name,
        role=user.role,
    )
    return TokenResponse(
        access_token=access_token,
        token_type='bearer',
        expires_in=900,
    )


@router.post(
    '/logout',
    status_code=HTTPStatus.NO_CONTENT,
)
async def logout() -> Response:
    """Encerra a sessão do usuário."""
    return Response(status_code=HTTPStatus.NO_CONTENT)
