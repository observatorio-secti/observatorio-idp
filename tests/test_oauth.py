import base64
import hashlib
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from app.core.keys import key_manager


def _generate_pkce_pair(
    verifier: str = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
):
    """Utilitário para gerar desafio S256."""
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
    return verifier, challenge


def test_jwks_retorna_chaves_publicas_rsa(client: TestClient):
    """Regra: Endpoint /.well-known/jwks.json expõe chaves públicas ativas no padrão RFC 7517."""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == HTTPStatus.OK
    data = response.json()
    assert 'keys' in data
    assert len(data['keys']) > 0

    key = data['keys'][0]
    assert key['kty'] == 'RSA'
    assert key['alg'] == 'RS256'
    assert key['use'] == 'sig'
    assert 'kid' in key
    assert 'n' in key
    assert 'e' in key


def test_authorize_redirect_uri_invalida_rejeita_sem_redirecionar(
    client: TestClient, application, user
):
    """Regra de Segurança: Se redirect_uri não for autorizada, o IdP DEVE rejeitar com erro sem redirecionar."""
    _, challenge = _generate_pkce_pair()
    params = {
        'client_id': application.client_id,
        'redirect_uri': 'https://site-malicioso.com/roubo',
        'response_type': 'code',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'user_id': str(user.id),
    }
    response = client.get('/authorize', params=params, follow_redirects=False)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'redirect_uri não autorizada' in response.json()['detail']


def test_authorize_client_id_inexistente_retorna_bad_request(
    client: TestClient, user
):
    """Regra: client_id não cadastrado é rejeitado imediatamente."""
    _, challenge = _generate_pkce_pair()
    params = {
        'client_id': 'cliente_fantasma_inexistente',
        'redirect_uri': 'http://localhost:3000/auth/callback',
        'response_type': 'code',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'user_id': str(user.id),
    }
    response = client.get('/authorize', params=params, follow_redirects=False)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'invalid_client' in response.json()['detail']


def test_jornada_oauth_authorization_code_pkce_e_rotacao(
    client: TestClient, application, user
):
    """Jornada completa:
    1. Usuário autoriza a aplicação com PKCE S256 e recebe o Authorization Code no redirect.
    2. Aplicação troca o código e verifier por access token RS256 e refresh token.
    3. Aplicação rotaciona o refresh token obtendo novo par de tokens.
    4. Tentativa de reúso do refresh token antigo dispara revogação da família.
    5. Token novo fica revogado após detecção de reúso.
    """
    verifier, challenge = _generate_pkce_pair()
    redirect_uri = application.redirect_uris[0]

    # Passo 1: Solicitação de autorização via /authorize
    auth_params = {
        'client_id': application.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': 'estado_anti_csrf_xyz',
        'user_id': str(user.id),
    }
    auth_response = client.get(
        '/authorize', params=auth_params, follow_redirects=False
    )
    assert auth_response.status_code == HTTPStatus.FOUND
    location = auth_response.headers['location']
    parsed_location = urlparse(location)
    query_params = parse_qs(parsed_location.query)
    assert 'code' in query_params
    assert query_params['state'][0] == 'estado_anti_csrf_xyz'
    raw_code = query_params['code'][0]

    # Passo 2: Troca de código com code_verifier incorreto deve falhar
    bad_token_payload = {
        'grant_type': 'authorization_code',
        'client_id': application.client_id,
        'code': raw_code,
        'redirect_uri': redirect_uri,
        'code_verifier': 'verificador_incorreto_errado',
    }
    bad_resp = client.post('/token', json=bad_token_payload)
    assert bad_resp.status_code == HTTPStatus.BAD_REQUEST
    assert 'code_verifier inválido' in bad_resp.json()['detail']

    # Passo 3: Troca de código com code_verifier correto (sucesso)
    token_payload = {
        'grant_type': 'authorization_code',
        'client_id': application.client_id,
        'code': raw_code,
        'redirect_uri': redirect_uri,
        'code_verifier': verifier,
    }
    token_response = client.post('/token', json=token_payload)
    assert token_response.status_code == HTTPStatus.OK
    token_data = token_response.json()
    assert 'access_token' in token_data
    assert 'refresh_token' in token_data
    refresh_token_1 = token_data['refresh_token']

    # Validação do Access Token emitido
    claims = key_manager.decode_jwt(token_data['access_token'])
    assert claims['sub'] == str(user.id)
    assert claims['aud'] == application.client_id

    # Passo 4: Tentativa de reutilizar o mesmo Authorization Code (uso único)
    reuse_code_resp = client.post('/token', json=token_payload)
    assert reuse_code_resp.status_code == HTTPStatus.BAD_REQUEST
    assert 'já utilizado' in reuse_code_resp.json()['detail']

    # Passo 5: Rotação válida de Refresh Token
    refresh_payload_1 = {
        'grant_type': 'refresh_token',
        'client_id': application.client_id,
        'refresh_token': refresh_token_1,
    }
    rot_resp_1 = client.post('/token', json=refresh_payload_1)
    assert rot_resp_1.status_code == HTTPStatus.OK
    rot_data_1 = rot_resp_1.json()
    assert 'access_token' in rot_data_1
    assert 'refresh_token' in rot_data_1
    refresh_token_2 = rot_data_1['refresh_token']
    assert refresh_token_2 != refresh_token_1

    # Passo 6: Detecção de Reúso (apresentar o refresh_token_1 novamente após ele já ter sido rotacionado)
    reuse_refresh_resp = client.post('/token', json=refresh_payload_1)
    assert reuse_refresh_resp.status_code == HTTPStatus.BAD_REQUEST
    assert (
        'reúso de refresh token detectada'
        in reuse_refresh_resp.json()['detail']
    )

    # Passo 7: Como a família inteira foi revogada, até o refresh_token_2 agora está inutilizado
    refresh_payload_2 = {
        'grant_type': 'refresh_token',
        'client_id': application.client_id,
        'refresh_token': refresh_token_2,
    }
    revoked_resp = client.post('/token', json=refresh_payload_2)
    assert revoked_resp.status_code == HTTPStatus.BAD_REQUEST
    assert 'revogado' in revoked_resp.json()['detail']


def test_pkce_metodo_plain(client: TestClient, application, user):
    """Regra: Suporte ao método PKCE 'plain' para clientes legados."""
    plain_verifier = 'simples_verificador_plain_12345'
    redirect_uri = application.redirect_uris[0]

    auth_params = {
        'client_id': application.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'code_challenge': plain_verifier,
        'code_challenge_method': 'plain',
        'user_id': str(user.id),
    }
    auth_response = client.get(
        '/authorize', params=auth_params, follow_redirects=False
    )
    assert auth_response.status_code == HTTPStatus.FOUND
    raw_code = parse_qs(urlparse(auth_response.headers['location']).query)[
        'code'
    ][0]

    token_payload = {
        'grant_type': 'authorization_code',
        'client_id': application.client_id,
        'code': raw_code,
        'redirect_uri': redirect_uri,
        'code_verifier': plain_verifier,
    }
    resp = client.post('/token', json=token_payload)
    assert resp.status_code == HTTPStatus.OK
    assert 'access_token' in resp.json()


def test_login_page_renders_html(client: TestClient, application):
    """Verifica se o endpoint GET /login renderiza a interface institucional com sucesso."""
    resp = client.get('/login')
    assert resp.status_code == HTTPStatus.OK
    assert 'text/html' in resp.headers['content-type']
    assert 'Observatório' in resp.text
    assert 'Continuar com Google' in resp.text
    assert 'Continuar com ORCID' in resp.text


def test_authorize_renders_html_when_unauthenticated(
    client: TestClient, application
):
    """Verifica se GET /authorize exibe a tela de login quando o usuário não está autenticado."""
    _, challenge = _generate_pkce_pair()
    auth_params = {
        'client_id': application.client_id,
        'redirect_uri': application.redirect_uris[0],
        'response_type': 'code',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': 'xyz_csrf',
    }
    resp = client.get(
        '/authorize', params=auth_params, headers={'Accept': 'text/html'}
    )
    assert resp.status_code == HTTPStatus.OK
    assert 'text/html' in resp.headers['content-type']
    assert application.client_id in resp.text
    assert challenge in resp.text


def test_authorize_post_login_success(client: TestClient, application, user):
    """Verifica se a submissão de formulário no IdP autentica o usuário e emite o Authorization Code."""
    verifier, challenge = _generate_pkce_pair()
    redirect_uri = application.redirect_uris[0]

    form_data = {
        'client_id': application.client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': 'my_state',
        'email': user.email,
        'password': user.raw_password,
        'action': 'login',
    }
    resp = client.post('/authorize', data=form_data, follow_redirects=False)
    assert resp.status_code == HTTPStatus.SEE_OTHER
    location = resp.headers['location']
    assert location.startswith(redirect_uri)
    parsed = parse_qs(urlparse(location).query)
    assert 'code' in parsed
    assert parsed['state'][0] == 'my_state'

    # Troca de código por token para validar a claim de role
    token_resp = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'client_id': application.client_id,
            'code': parsed['code'][0],
            'redirect_uri': redirect_uri,
            'code_verifier': verifier,
        },
    )
    assert token_resp.status_code == HTTPStatus.OK
    token_data = token_resp.json()
    claims = key_manager.decode_jwt(token_data['access_token'])
    assert claims.get('role') == 'DEFAULT'
