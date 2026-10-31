import base64
import hashlib
import os
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.core.security import get_password_hash
from app.models.user import User
from app.services.application_service import ApplicationService


def generate_pkce_pair():
    verifier_bytes = os.urandom(32)
    code_verifier = (
        base64.urlsafe_b64encode(verifier_bytes).decode('utf-8').rstrip('=')
    )
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    return code_verifier, code_challenge


@pytest.mark.asyncio
async def test_complete_e2e_pkce_registration_and_login_flow(
    client: TestClient, session
):
    """Testa o fluxo ponta a ponta:

    1. GET /authorize renderiza tela de login com PKCE
    2. POST /authorize cadastra usuário novo e emite authorization code
    3. POST /token troca o code + verifier pelo par de tokens RS256
    4. GET /me consulta o perfil autenticado com a claim de role
    5. POST /token rotaciona o refresh token
    """
    await ApplicationService.seed_default_applications(session)

    verifier, challenge = generate_pkce_pair()
    client_id = 'observatorio'
    redirect_uri = 'http://localhost:5173/auth/callback'
    state = 'random_state_123'

    # 1. GET /authorize sem login deve retornar a página HTML de login
    resp_get = client.get(
        f'/authorize?client_id={client_id}&redirect_uri={redirect_uri}'
        f'&response_type=code&code_challenge={challenge}&code_challenge_method=S256&state={state}'
    )
    assert resp_get.status_code == HTTPStatus.OK
    assert 'text/html' in resp_get.headers['content-type']
    assert 'Observatório' in resp_get.text

    # 2. POST /authorize com cadastro de nova conta
    new_email = f'novo_{os.urandom(4).hex()}@teste.com'
    resp_post = client.post(
        '/authorize',
        data={
            'action': 'register',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'state': state,
            'name': 'Usuário de Teste E2E',
            'email': new_email,
            'password': 'SenhaSegura123!',
        },
        follow_redirects=False,
    )
    assert resp_post.status_code == HTTPStatus.SEE_OTHER
    redirect_url = resp_post.headers['location']
    parsed = urlparse(redirect_url)
    assert parsed.netloc == 'localhost:5173'
    assert parsed.path == '/auth/callback'
    params = parse_qs(parsed.query)
    assert 'code' in params
    assert params['state'][0] == state
    code = params['code'][0]

    # 3. POST /token troca o code pelo token RS256
    resp_token = client.post(
        '/token',
        json={
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'code': code,
            'redirect_uri': redirect_uri,
            'code_verifier': verifier,
        },
    )
    assert resp_token.status_code == HTTPStatus.OK
    token_data = resp_token.json()
    assert 'access_token' in token_data
    assert 'refresh_token' in token_data
    assert token_data['token_type'].lower() == 'bearer'
    access_token = token_data['access_token']
    refresh_token = token_data['refresh_token']

    # 4. GET /me consulta perfil
    resp_me = client.get(
        '/me',
        headers={'Authorization': f'Bearer {access_token}'},
    )
    assert resp_me.status_code == HTTPStatus.OK
    me_data = resp_me.json()
    assert me_data['email'] == new_email
    assert me_data['name'] == 'Usuário de Teste E2E'
    assert me_data['role'] == 'DEFAULT'

    # 5. POST /token para rotação
    resp_rot = client.post(
        '/token',
        json={
            'grant_type': 'refresh_token',
            'client_id': client_id,
            'refresh_token': refresh_token,
        },
    )
    assert resp_rot.status_code == HTTPStatus.OK
    rot_data = resp_rot.json()
    assert 'access_token' in rot_data
    assert rot_data['access_token'] != access_token


@pytest.mark.asyncio
async def test_simcc_pkce_login_existing_user_admin(
    client: TestClient, session
):
    """Testa o fluxo ponta a ponta com a aplicação simcc (porta 8080):

    1. Cadastra usuário local
    2. Promove para ADMIN
    3. Realiza login direto no POST /authorize
    4. Troca code por token e valida role == 'ADMIN' no /me
    """
    await ApplicationService.seed_default_applications(session)

    # Cria usuário admin no banco
    admin_user = User(
        email='admin_simcc@teste.com',
        name='Admin SimCC',
        password_hash=get_password_hash('SenhaAdmin123!'),
        role='ADMIN',
        is_active=True,
    )
    session.add(admin_user)
    await session.commit()

    verifier, challenge = generate_pkce_pair()
    client_id = 'simcc'
    redirect_uri = 'http://localhost:8080/auth/callback'
    state = 'simcc_state_456'

    # Login
    resp_post = client.post(
        '/authorize',
        data={
            'action': 'login',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'code_challenge': challenge,
            'code_challenge_method': 'S256',
            'state': state,
            'email': 'admin_simcc@teste.com',
            'password': 'SenhaAdmin123!',
        },
        follow_redirects=False,
    )
    assert resp_post.status_code == HTTPStatus.SEE_OTHER
    redirect_url = resp_post.headers['location']
    params = parse_qs(urlparse(redirect_url).query)
    code = params['code'][0]

    # Troca code por token
    resp_token = client.post(
        '/token',
        json={
            'grant_type': 'authorization_code',
            'client_id': client_id,
            'code': code,
            'redirect_uri': redirect_uri,
            'code_verifier': verifier,
        },
    )
    assert resp_token.status_code == HTTPStatus.OK
    access_token = resp_token.json()['access_token']

    # Perfil retorna role ADMIN
    resp_me = client.get(
        '/me',
        headers={'Authorization': f'Bearer {access_token}'},
    )
    assert resp_me.status_code == HTTPStatus.OK
    me_data = resp_me.json()
    assert me_data['email'] == 'admin_simcc@teste.com'
    assert me_data['role'] == 'ADMIN'
