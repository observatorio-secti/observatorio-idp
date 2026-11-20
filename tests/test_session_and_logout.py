import re
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_token
from app.main import app
from app.models.token import IdpSession, RefreshToken
from app.oauth.base import OAuthUserInfo
from tests.test_oauth import _generate_pkce_pair


def _authorize_params(
    application,
    challenge: str,
    state: str = 'csrf_state_1',
    prompt: str | None = None,
) -> dict[str, str]:
    params = {
        'client_id': application.client_id,
        'redirect_uri': application.redirect_uris[0],
        'response_type': 'code',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': state,
    }
    if prompt is not None:
        params['prompt'] = prompt
    return params


def test_post_authorize_grava_cookie_e_permite_sso_e_prompt_none(
    client: TestClient, application, user
):
    """Após login em POST /authorize, o cookie idp_session permite prompt=none e SSO silencioso."""
    verifier, challenge = _generate_pkce_pair()
    redirect_uri = application.redirect_uris[0]

    login_resp = client.post(
        '/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'state': 'st_login',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        follow_redirects=False,
    )
    assert login_resp.status_code == HTTPStatus.SEE_OTHER
    set_cookie = login_resp.headers.get('set-cookie', '')
    assert f'{settings.SESSION_COOKIE_NAME}=' in set_cookie
    assert 'HttpOnly' in set_cookie
    assert settings.SESSION_COOKIE_NAME in client.cookies

    # Recarregamento da página com prompt=none emite novo authorization_code sem exibir login
    verifier_2, challenge_2 = _generate_pkce_pair(
        'second_verifier_with_enough_length_0123456789'
    )
    silent_resp = client.get(
        '/authorize',
        params=_authorize_params(
            application, challenge_2, state='st_silent', prompt='none'
        ),
        follow_redirects=False,
    )
    assert silent_resp.status_code == HTTPStatus.FOUND
    silent_qs = parse_qs(urlparse(silent_resp.headers['location']).query)
    assert 'code' in silent_qs
    assert silent_qs['state'] == ['st_silent']

    # O código emitido pelo prompt=none troca normalmente por access/refresh tokens
    token_resp = client.post(
        '/token',
        json={
            'grant_type': 'authorization_code',
            'client_id': application.client_id,
            'code': silent_qs['code'][0],
            'redirect_uri': redirect_uri,
            'code_verifier': verifier_2,
        },
    )
    assert token_resp.status_code == HTTPStatus.OK
    assert 'access_token' in token_resp.json()

    # Também funciona sem prompt explícito (SSO padrão)
    _, challenge_3 = _generate_pkce_pair(
        'third_verifier_with_enough_length_0123456789'
    )
    sso_resp = client.get(
        '/authorize',
        params=_authorize_params(application, challenge_3, state='st_sso'),
        follow_redirects=False,
    )
    assert sso_resp.status_code == HTTPStatus.FOUND
    sso_qs = parse_qs(urlparse(sso_resp.headers['location']).query)
    assert 'code' in sso_qs
    assert sso_qs['state'] == ['st_sso']

    # Verifica que o verifier original também era válido para o primeiro código
    first_code = parse_qs(urlparse(login_resp.headers['location']).query)[
        'code'
    ][0]
    first_token_resp = client.post(
        '/token',
        json={
            'grant_type': 'authorization_code',
            'client_id': application.client_id,
            'code': first_code,
            'redirect_uri': redirect_uri,
            'code_verifier': verifier,
        },
    )
    assert first_token_resp.status_code == HTTPStatus.OK


def test_prompt_none_sem_sessao_redireciona_com_login_required(
    client: TestClient, application
):
    """GET /authorize?prompt=none sem sessão redireciona para redirect_uri com error=login_required."""
    _, challenge = _generate_pkce_pair()
    params = _authorize_params(
        application, challenge, state='st_err', prompt='none'
    )

    resp = client.get(
        '/authorize',
        params=params,
        headers={'Accept': 'application/json'},
        follow_redirects=False,
    )
    assert resp.status_code == HTTPStatus.FOUND
    location = resp.headers['location']
    assert location.startswith(application.redirect_uris[0])
    qs = parse_qs(urlparse(location).query)
    assert qs['error'] == ['login_required']
    assert qs['state'] == ['st_err']


def test_prompt_none_nao_redireciona_para_redirect_uri_invalida(
    client: TestClient, application
):
    """Segurança RFC 6749: redirect_uri inválida com prompt=none rejeita 400 sem redirecionar."""
    _, challenge = _generate_pkce_pair()
    resp = client.get(
        '/authorize',
        params={
            'client_id': application.client_id,
            'redirect_uri': 'https://evil.example/cb',
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'prompt': 'none',
        },
        follow_redirects=False,
    )
    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_prompt_login_forca_tela_de_login_mesmo_com_sessao_ativa(
    client: TestClient, application, user
):
    """GET /authorize?prompt=login ignora o cookie existente e exibe a tela de login."""
    _, challenge = _generate_pkce_pair()
    client.post(
        '/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': application.redirect_uris[0],
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        follow_redirects=False,
    )

    resp = client.get(
        '/authorize',
        params=_authorize_params(application, challenge, prompt='login'),
        headers={'Accept': 'text/html'},
        follow_redirects=False,
    )
    assert resp.status_code == HTTPStatus.OK
    assert 'text/html' in resp.headers['content-type']
    assert 'Observatório' in resp.text


def test_prompt_invalido_redireciona_com_invalid_request(
    client: TestClient, application
):
    """Combinação inválida (ex.: 'none login') redireciona com error=invalid_request."""
    _, challenge = _generate_pkce_pair()
    resp = client.get(
        '/authorize',
        params=_authorize_params(
            application, challenge, state='st_bad', prompt='none login'
        ),
        follow_redirects=False,
    )
    assert resp.status_code == HTTPStatus.FOUND
    qs = parse_qs(urlparse(resp.headers['location']).query)
    assert qs['error'] == ['invalid_request']
    assert qs['state'] == ['st_bad']


async def test_prompt_none_com_sessao_expirada_limpa_cookie_e_retorna_login_required(
    client: TestClient, session: AsyncSession, application, user
):
    """Sessão expirada no banco resulta em login_required e remoção do cookie."""
    _, challenge = _generate_pkce_pair()
    client.post(
        '/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': application.redirect_uris[0],
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        follow_redirects=False,
    )

    raw_cookie = client.cookies.get(settings.SESSION_COOKIE_NAME)
    assert raw_cookie
    db_sess = await session.scalar(
        select(IdpSession).where(
            IdpSession.token_hash == hash_token(raw_cookie)
        )
    )
    assert db_sess is not None
    db_sess.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    await session.commit()

    resp = client.get(
        '/authorize',
        params=_authorize_params(
            application, challenge, state='st_exp', prompt='none'
        ),
        follow_redirects=False,
    )
    assert resp.status_code == HTTPStatus.FOUND
    qs = parse_qs(urlparse(resp.headers['location']).query)
    assert qs['error'] == ['login_required']
    assert qs['state'] == ['st_exp']
    assert settings.SESSION_COOKIE_NAME not in client.cookies


def test_callback_federado_pkce_grava_sessao_e_permite_prompt_none(
    client: TestClient, application
):
    """Login via provedor federado (Google) no fluxo PKCE cria sessão no IdP."""
    _, challenge = _generate_pkce_pair()
    auth_page = client.get(
        '/authorize',
        params=_authorize_params(application, challenge, state='fed_state'),
        headers={'Accept': 'text/html'},
    )
    assert auth_page.status_code == HTTPStatus.OK
    match = re.search(
        r'href="/auth/google/login\?state=([^"]+)"', auth_page.text
    )
    assert match is not None
    encoded_state = match.group(1)
    mock_info = OAuthUserInfo(
        provider='google',
        provider_user_id='google_sso_123',
        email='federado.sso@gmail.com',
        name='Federado SSO',
        email_verified=True,
    )

    with patch(
        'app.oauth.google.GoogleOAuthProvider.get_user_info',
        new_callable=AsyncMock,
        return_value=mock_info,
    ):
        cb_resp = client.get(
            f'/auth/google/callback?code=mock_code&state={encoded_state}',
            follow_redirects=False,
        )
        assert cb_resp.status_code == HTTPStatus.TEMPORARY_REDIRECT
        assert settings.SESSION_COOKIE_NAME in client.cookies

    silent_resp = client.get(
        '/authorize',
        params=_authorize_params(
            application, challenge, state='after_fed', prompt='none'
        ),
        follow_redirects=False,
    )
    assert silent_resp.status_code == HTTPStatus.FOUND
    qs = parse_qs(urlparse(silent_resp.headers['location']).query)
    assert 'code' in qs
    assert qs['state'] == ['after_fed']


async def test_end_session_get_revoga_sessao_e_refresh_tokens_e_redireciona(
    client: TestClient, session: AsyncSession, application, user
):
    """GET /end_session revoga IdpSession e RefreshTokens, limpa cookie e redireciona."""
    verifier, challenge = _generate_pkce_pair()
    redirect_uri = application.redirect_uris[0]

    login_resp = client.post(
        '/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        follow_redirects=False,
    )
    code = parse_qs(urlparse(login_resp.headers['location']).query)['code'][0]
    raw_cookie = client.cookies.get(settings.SESSION_COOKIE_NAME)
    assert raw_cookie

    token_resp = client.post(
        '/token',
        json={
            'grant_type': 'authorization_code',
            'client_id': application.client_id,
            'code': code,
            'redirect_uri': redirect_uri,
            'code_verifier': verifier,
        },
    )
    refresh_token = token_resp.json()['refresh_token']

    post_logout_uri = 'http://localhost:3000/simcc/'
    end_resp = client.get(
        '/end_session',
        params={
            'post_logout_redirect_uri': post_logout_uri,
            'state': 'bye_123',
            'client_id': application.client_id,
        },
        follow_redirects=False,
    )
    assert end_resp.status_code == HTTPStatus.FOUND
    location = end_resp.headers['location']
    assert location.startswith(post_logout_uri)
    assert parse_qs(urlparse(location).query)['state'] == ['bye_123']
    assert settings.SESSION_COOKIE_NAME not in client.cookies

    # Replay do cookie antigo também deve falhar (revogado no banco)
    client.cookies.set(settings.SESSION_COOKIE_NAME, raw_cookie)
    silent_after = client.get(
        '/authorize',
        params=_authorize_params(application, challenge, prompt='none'),
        follow_redirects=False,
    )
    assert silent_after.status_code == HTTPStatus.FOUND
    assert parse_qs(urlparse(silent_after.headers['location']).query)[
        'error'
    ] == ['login_required']

    # Refresh token também foi revogado
    rot_resp = client.post(
        '/token',
        json={
            'grant_type': 'refresh_token',
            'client_id': application.client_id,
            'refresh_token': refresh_token,
        },
    )
    assert rot_resp.status_code == HTTPStatus.BAD_REQUEST
    assert 'revogado' in rot_resp.json()['detail']

    db_rt = await session.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(refresh_token)
        )
    )
    assert db_rt is not None and db_rt.revoked_at is not None


def test_end_session_post_sem_redirect_retorna_204_e_rejeita_origem_externa(
    client: TestClient, application, user
):
    """POST /end_session sem redirect retorna 204; URI externa não autorizada retorna 400."""
    _, challenge = _generate_pkce_pair()
    client.post(
        '/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': application.redirect_uris[0],
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        follow_redirects=False,
    )

    bad_resp = client.get(
        '/end_session',
        params={'post_logout_redirect_uri': 'https://malicioso.exemplo/sair'},
        follow_redirects=False,
    )
    assert bad_resp.status_code == HTTPStatus.BAD_REQUEST

    ok_resp = client.post('/end_session', follow_redirects=False)
    assert ok_resp.status_code == HTTPStatus.NO_CONTENT
    assert settings.SESSION_COOKIE_NAME not in client.cookies


def test_auth_logout_tambem_revoga_sessao_do_cookie(
    client: TestClient, application, user
):
    """POST /auth/logout mantém 204 e revoga/remove o cookie idp_session."""
    _, challenge = _generate_pkce_pair()
    client.post(
        '/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': application.redirect_uris[0],
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        follow_redirects=False,
    )
    assert settings.SESSION_COOKIE_NAME in client.cookies

    resp = client.post('/auth/logout')
    assert resp.status_code == HTTPStatus.NO_CONTENT
    assert settings.SESSION_COOKIE_NAME not in client.cookies


def test_proxy_prefix_e_https_no_cookie_e_end_session(
    proxied_client: TestClient, application, user
):
    """Atrás de proxy (/idp + X-Forwarded-Proto: https), cookie recebe Secure e end_session funciona."""
    _, challenge = _generate_pkce_pair()
    headers = {'X-Forwarded-Proto': 'https'}

    # 1. Mesmo via HTTP interno com X-Forwarded-Proto: https, o cookie é marcado como Secure
    forwarded_resp = proxied_client.post(
        '/idp/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': application.redirect_uris[0],
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        headers=headers,
        follow_redirects=False,
    )
    assert forwarded_resp.status_code == HTTPStatus.SEE_OTHER
    set_cookie = forwarded_resp.headers.get('set-cookie', '')
    assert 'Secure' in set_cookie
    assert 'HttpOnly' in set_cookie

    # 2. Cliente HTTPS atrás do proxy envia o cookie Secure normalmente para prompt=none e end_session
    https_proxied = TestClient(
        app, base_url='https://testserver', root_path='/idp'
    )
    login_resp = https_proxied.post(
        '/idp/authorize',
        data={
            'client_id': application.client_id,
            'redirect_uri': application.redirect_uris[0],
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'email': user.email,
            'password': user.raw_password,
            'action': 'login',
        },
        follow_redirects=False,
    )
    assert login_resp.status_code == HTTPStatus.SEE_OTHER
    assert 'Secure' in login_resp.headers.get('set-cookie', '')

    silent_resp = https_proxied.get(
        '/idp/authorize',
        params=_authorize_params(
            application, challenge, state='proxy_silent', prompt='none'
        ),
        follow_redirects=False,
    )
    assert silent_resp.status_code == HTTPStatus.FOUND
    assert 'code' in parse_qs(urlparse(silent_resp.headers['location']).query)

    end_resp = https_proxied.get(
        '/idp/end_session',
        headers={'Accept': 'text/html'},
        follow_redirects=False,
    )
    assert end_resp.status_code == HTTPStatus.FOUND
    assert end_resp.headers['location'] == '/idp/login'
    assert settings.SESSION_COOKIE_NAME not in https_proxied.cookies
