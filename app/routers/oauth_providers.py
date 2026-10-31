import base64
import json
from http import HTTPStatus
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.core.dependencies import DbSession
from app.core.keys import create_access_token
from app.core.security import generate_secure_token
from app.oauth.registry import get_oauth_provider
from app.services.account_service import AccountService
from app.services.token_service import TokenService

router = APIRouter(prefix='/auth', tags=['federated-auth'])


@router.get('/{provider}/login')
async def oauth_login(
    provider: str,
    state: str | None = Query(
        default=None, description='Estado CSRF customizado (opcional)'
    ),
) -> RedirectResponse:
    """Inicia o fluxo de autorização com um provedor OAuth externo (Google ou ORCID)."""
    try:
        oauth_provider = get_oauth_provider(provider, settings)
    except ValueError as e:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=str(e),
        ) from e

    csrf_state = state or generate_secure_token(32)
    auth_url = oauth_provider.get_authorization_url(state=csrf_state)
    return RedirectResponse(
        url=auth_url, status_code=HTTPStatus.TEMPORARY_REDIRECT
    )


@router.get('/{provider}/callback')
async def oauth_callback(
    provider: str,
    code: str,
    session: DbSession,
    state: str | None = None,
) -> RedirectResponse:
    """Recebe o retorno do provedor OAuth externo, autentica/vincula a conta e redireciona com o token ou authorization code."""
    try:
        oauth_provider = get_oauth_provider(provider, settings)
    except ValueError as e:
        raise HTTPException(
            status_code=HTTPStatus.NOT_FOUND,
            detail=str(e),
        ) from e

    try:
        user_info = await oauth_provider.get_user_info(code=code)
    except (httpx.HTTPError, ValueError, KeyError) as e:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail=f'Falha na comunicação com o provedor {provider}: {e!s}',
        ) from e

    user = await AccountService.authenticate_or_link_federated_user(
        session, user_info
    )

    # Verifica se o state carrega contexto PKCE da aplicação cliente
    pkce_data = None
    if state and state.startswith('pkce_'):
        try:
            raw_json = base64.urlsafe_b64decode(
                state[5:].encode('ascii')
            ).decode('utf-8')
            pkce_data = json.loads(raw_json)
        except Exception:
            pkce_data = None

    if (
        pkce_data
        and 'client_id' in pkce_data
        and 'redirect_uri' in pkce_data
        and 'code_challenge' in pkce_data
    ):
        raw_code = await TokenService.create_authorization_code(
            session=session,
            client_id=pkce_data['client_id'],
            user_id=user.id,
            redirect_uri=pkce_data['redirect_uri'],
            code_challenge=pkce_data['code_challenge'],
            code_challenge_method=pkce_data.get(
                'code_challenge_method', 'S256'
            ),
        )
        params = {'code': raw_code}
        if pkce_data.get('orig_state'):
            params['state'] = pkce_data['orig_state']

        separator = '&' if '?' in pkce_data['redirect_uri'] else '?'
        return RedirectResponse(
            url=f'{pkce_data["redirect_uri"]}{separator}{urlencode(params)}',
            status_code=HTTPStatus.TEMPORARY_REDIRECT,
        )

    # Fluxo legado/direto (emite access token direto)
    access_token = create_access_token(
        user_id=str(user.id),
        email=user.email,
        name=user.name,
        role=user.role,
    )

    params = urlencode({'token': access_token, 'token_type': 'bearer'})
    separator = '&' if '?' in settings.FRONTEND_AUTH_CALLBACK_URL else '?'
    redirect_target = (
        f'{settings.FRONTEND_AUTH_CALLBACK_URL}{separator}{params}'
    )

    return RedirectResponse(
        url=redirect_target,
        status_code=HTTPStatus.TEMPORARY_REDIRECT,
    )
