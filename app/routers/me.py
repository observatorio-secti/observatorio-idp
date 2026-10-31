from http import HTTPStatus

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.core.dependencies import CurrentUser, DbSession
from app.core.security import generate_secure_token
from app.oauth.registry import get_oauth_provider
from app.schemas.user import IdentityPublic, UserPublic
from app.services.account_service import AccountService

router = APIRouter(prefix='/me', tags=['me'])


@router.get('', response_model=UserPublic)
async def get_profile(
    current_user: CurrentUser,
    session: DbSession,
) -> UserPublic:
    """Retorna os dados do perfil autenticado, status de senha e identidades conectadas."""
    user = await AccountService.get_by_id(session, current_user.id)
    if not user:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail='Usuário não encontrado.',
        )

    return UserPublic(
        id=user.id,
        email=user.email,
        name=user.name,
        is_active=user.is_active,
        role=user.role,
        has_password=user.password_hash is not None,
        created_at=user.created_at,
        identities=[
            IdentityPublic(
                provider=i.provider,
                provider_user_id=i.provider_user_id,
                email=i.email,
                created_at=i.created_at,
            )
            for i in user.identities
        ],
    )


@router.post('/identities/{provider}')
async def start_identity_linking(
    provider: str,
    current_user: CurrentUser,
) -> RedirectResponse:
    """Inicia o fluxo para conectar um novo provedor OAuth à conta autenticada."""
    try:
        oauth_provider = get_oauth_provider(provider, settings)
    except ValueError as e:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=str(e),
        ) from e

    link_state = f'link_{current_user.id}_{generate_secure_token(16)}'
    auth_url = oauth_provider.get_authorization_url(state=link_state)
    return RedirectResponse(
        url=auth_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
    )


@router.delete('/identities/{provider}', status_code=HTTPStatus.NO_CONTENT)
async def unlink_identity(
    provider: str,
    current_user: CurrentUser,
    session: DbSession,
) -> Response:
    """Remove a vinculação da conta com o provedor especificado.

    A remoção é recusada se este for o único método de autenticação restante
    (usuário sem senha e sem outros provedores).
    """
    await AccountService.unlink_identity(session, current_user, provider)
    return Response(status_code=HTTPStatus.NO_CONTENT)
