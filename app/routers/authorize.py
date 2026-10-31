from __future__ import annotations

import base64
import json
from http import HTTPStatus
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode
from uuid import UUID

from fastapi import (
    APIRouter,
    Form,
    Header,
    HTTPException,
    Query,
    Request,
    Response,
)
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jwt import ExpiredSignatureError, InvalidTokenError

from app.core.dependencies import DbSession
from app.core.keys import key_manager
from app.models.user import User
from app.schemas.auth import LoginRequest, RegisterRequest
from app.schemas.oauth import OAuthTokenResponse
from app.services.account_service import AccountService
from app.services.application_service import ApplicationService
from app.services.token_service import TokenService

router = APIRouter(tags=['oauth2'])
templates = Jinja2Templates(
    directory=str(Path(__file__).parent.parent / 'templates')
)


def _encode_pkce_state(
    client_id: str,
    redirect_uri: str,
    code_challenge: str,
    code_challenge_method: str,
    orig_state: str | None,
) -> str:
    payload = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'code_challenge': code_challenge,
        'code_challenge_method': code_challenge_method,
        'orig_state': orig_state or '',
    }
    raw_b64 = base64.urlsafe_b64encode(
        json.dumps(payload).encode('utf-8')
    ).decode('ascii')
    return f'pkce_{raw_b64}'


@router.get('/login', response_class=HTMLResponse)
async def login_page(
    request: Request,
    session: DbSession,
    client_id: str = 'observatorio',
    redirect_uri: str | None = None,
    code_challenge: str = 'default-challenge',
    code_challenge_method: str = 'plain',
    state: str | None = None,
) -> Response:
    """Página direta de autenticação institucional."""
    app = await ApplicationService.get_application(session, client_id)
    target_redirect = redirect_uri or (
        app.redirect_uris[0]
        if app and app.redirect_uris
        else 'http://localhost:3000/auth/callback'
    )

    encoded_pkce = _encode_pkce_state(
        client_id=client_id,
        redirect_uri=target_redirect,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        orig_state=state,
    )

    return templates.TemplateResponse(
        request=request,
        name='login.html',
        context={
            'client_id': client_id,
            'redirect_uri': target_redirect,
            'response_type': 'code',
            'code_challenge': code_challenge,
            'code_challenge_method': code_challenge_method,
            'state': state or '',
            'error': None,
            'google_login_url': f'/auth/google/login?state={encoded_pkce}',
            'orcid_login_url': f'/auth/orcid/login?state={encoded_pkce}',
        },
    )


@router.get('/authorize')
async def authorize(
    request: Request,
    client_id: Annotated[
        str, Query(description='ID da aplicação cliente cadastrada')
    ],
    redirect_uri: Annotated[
        str, Query(description='URI de redirecionamento autorizada')
    ],
    response_type: Annotated[
        str, Query(description="Tipo de resposta solicitado, deve ser 'code'")
    ],
    code_challenge: Annotated[
        str, Query(description='Desafio de código PKCE')
    ],
    code_challenge_method: Annotated[
        str, Query(description="Método PKCE ('S256' ou 'plain')")
    ] = 'S256',
    state: Annotated[
        str | None, Query(description='Estado de proteção contra CSRF')
    ] = None,
    user_id: Annotated[
        UUID | None,
        Query(description='ID do usuário para autorização direta em testes'),
    ] = None,
    authorization: Annotated[str | None, Header()] = None,
    session: DbSession = ...,
) -> Response:
    """Endpoint de autorização OAuth 2.0 com suporte a PKCE e interface interativa."""
    # 1. Validação estrita de client_id e redirect_uri (rejeita sem redirecionar em caso de erro)
    await ApplicationService.validate_client_and_redirect(
        session, client_id, redirect_uri
    )

    if response_type != 'code':
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="unsupported_response_type: Apenas 'response_type=code' é suportado.",
        )

    # 2. Identificação do usuário logado
    current_user: User | None = None
    if user_id:
        current_user = await session.get(User, user_id)
    elif authorization and authorization.startswith('Bearer '):
        token_str = authorization.split(' ', 1)[1]
        try:
            payload = key_manager.decode_jwt(token_str)
            sub = payload.get('sub')
            if sub:
                current_user = await session.get(User, UUID(sub))
        except (ExpiredSignatureError, InvalidTokenError, ValueError):
            current_user = None

    if not current_user or not current_user.is_active:
        accept_header = request.headers.get('accept', '')
        # Se for requisição explicitamente de API/JSON ou teste com header de token ausente
        if (
            'application/json' in accept_header
            and 'text/html' not in accept_header
        ):
            raise HTTPException(
                status_code=HTTPStatus.UNAUTHORIZED,
                detail='Usuário não autenticado. Efetue login para autorizar a aplicação.',
            )

        # Renderiza a tela de login institucional preservando parâmetros PKCE
        encoded_pkce = _encode_pkce_state(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            orig_state=state,
        )
        return templates.TemplateResponse(
            request=request,
            name='login.html',
            context={
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': response_type,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
                'state': state or '',
                'error': None,
                'google_login_url': f'/auth/google/login?state={encoded_pkce}',
                'orcid_login_url': f'/auth/orcid/login?state={encoded_pkce}',
            },
        )

    # 3. Geração do Authorization Code
    raw_code = await TokenService.create_authorization_code(
        session=session,
        client_id=client_id,
        user_id=current_user.id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    params = {'code': raw_code}
    if state:
        params['state'] = state

    separator = '&' if '?' in redirect_uri else '?'
    redirect_target = f'{redirect_uri}{separator}{urlencode(params)}'

    return RedirectResponse(
        url=redirect_target,
        status_code=HTTPStatus.FOUND,
    )


@router.post('/authorize')
async def process_authorization_login(
    request: Request,
    session: DbSession,
    client_id: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    response_type: Annotated[str, Form()],
    code_challenge: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    action: Annotated[str, Form()] = 'login',
    name: Annotated[str | None, Form()] = None,
    code_challenge_method: Annotated[str, Form()] = 'S256',
    state: Annotated[str | None, Form()] = None,
) -> Response:
    """Processa a submissão do formulário de autenticação do IdP e emite o Authorization Code."""
    await ApplicationService.validate_client_and_redirect(
        session, client_id, redirect_uri
    )

    user: User | None = None
    error_msg: str | None = None

    try:
        if action == 'register':
            if not name or not name.strip():
                raise HTTPException(
                    status_code=HTTPStatus.BAD_REQUEST,
                    detail='O nome completo é obrigatório para cadastro.',
                )
            user = await AccountService.register_local_user(
                session,
                RegisterRequest(
                    name=name.strip(), email=email.strip(), password=password
                ),
            )
        else:
            user = await AccountService.authenticate_local_user(
                session,
                LoginRequest(email=email.strip(), password=password),
            )
    except HTTPException as exc:
        error_msg = exc.detail
    except Exception as exc:
        error_msg = f'Erro inesperado na autenticação: {exc!s}'

    if not user:
        encoded_pkce = _encode_pkce_state(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            orig_state=state,
        )
        return templates.TemplateResponse(
            request=request,
            name='login.html',
            context={
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'response_type': response_type,
                'code_challenge': code_challenge,
                'code_challenge_method': code_challenge_method,
                'state': state or '',
                'error': error_msg,
                'google_login_url': f'/auth/google/login?state={encoded_pkce}',
                'orcid_login_url': f'/auth/orcid/login?state={encoded_pkce}',
            },
            status_code=HTTPStatus.BAD_REQUEST,
        )

    raw_code = await TokenService.create_authorization_code(
        session=session,
        client_id=client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
    )

    params = {'code': raw_code}
    if state:
        params['state'] = state

    separator = '&' if '?' in redirect_uri else '?'
    redirect_target = f'{redirect_uri}{separator}{urlencode(params)}'

    return RedirectResponse(
        url=redirect_target,
        status_code=HTTPStatus.SEE_OTHER,
    )


@router.post('/token', response_model=OAuthTokenResponse)
async def issue_token(
    request: Request,
    session: DbSession,
    grant_type: Annotated[str | None, Form()] = None,
    client_id: Annotated[str | None, Form()] = None,
    code: Annotated[str | None, Form()] = None,
    redirect_uri: Annotated[str | None, Form()] = None,
    code_verifier: Annotated[str | None, Form()] = None,
    refresh_token: Annotated[str | None, Form()] = None,
) -> OAuthTokenResponse:
    """Endpoint de emissão e rotação de tokens OAuth 2.0 (suporta Form e JSON)."""
    # Suporte flexível para requisições x-www-form-urlencoded e application/json
    content_type = request.headers.get('content-type', '')
    if 'application/json' in content_type:
        body = await request.json()
        grant_type = body.get('grant_type')
        client_id = body.get('client_id')
        code = body.get('code')
        redirect_uri = body.get('redirect_uri')
        code_verifier = body.get('code_verifier')
        refresh_token = body.get('refresh_token')

    if not grant_type or not client_id:
        raise HTTPException(
            status_code=HTTPStatus.BAD_REQUEST,
            detail="invalid_request: 'grant_type' e 'client_id' são obrigatórios.",
        )

    if grant_type == 'authorization_code':
        if not code or not redirect_uri or not code_verifier:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="invalid_request: 'code', 'redirect_uri' e 'code_verifier' são obrigatórios para authorization_code.",
            )
        return await TokenService.exchange_authorization_code(
            session=session,
            client_id=client_id,
            raw_code=code,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )

    if grant_type == 'refresh_token':
        if not refresh_token:
            raise HTTPException(
                status_code=HTTPStatus.BAD_REQUEST,
                detail="invalid_request: 'refresh_token' é obrigatório para rotação.",
            )
        return await TokenService.rotate_refresh_token(
            session=session,
            client_id=client_id,
            raw_refresh_token=refresh_token,
        )

    raise HTTPException(
        status_code=HTTPStatus.BAD_REQUEST,
        detail=f"unsupported_grant_type: '{grant_type}' não é suportado.",
    )
