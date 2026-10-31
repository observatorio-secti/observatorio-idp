from http import HTTPStatus

from fastapi.testclient import TestClient

from app.core.keys import create_access_token


def test_me_sem_token_retorna_401(client: TestClient):
    """Regra: Rotas sob /me exigem autenticação Bearer JWT."""
    response = client.get('/me')
    assert response.status_code == HTTPStatus.UNAUTHORIZED


def test_me_retorna_perfil_e_identidades(
    client: TestClient, user, auth_headers
):
    """Regra: GET /me retorna perfil, status de senha e identidades conectadas."""
    response = client.get('/me', headers=auth_headers)
    assert response.status_code == HTTPStatus.OK
    data = response.json()
    assert data['id'] == str(user.id)
    assert data['email'] == user.email
    assert data['name'] == user.name
    assert data['has_password'] is True
    assert isinstance(data['identities'], list)


def test_iniciar_vinculacao_me_identities_redireciona(
    client: TestClient, user, auth_headers
):
    """Regra: POST /me/identities/{provider} inicia o fluxo com state contendo o id do usuário."""
    response = client.post(
        '/me/identities/google', headers=auth_headers, follow_redirects=False
    )
    assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    location = response.headers['location']
    assert 'accounts.google.com' in location
    assert f'link_{user.id}' in location


async def test_desvincular_identidade_permitido_se_usuario_tem_senha(
    client: TestClient, user, identity_generator
):
    """Regra: Se o usuário tem senha cadastrada, ele pode remover suas contas sociais conectadas."""
    await identity_generator(
        user, provider='google', provider_user_id='google_123'
    )
    token = create_access_token(
        user_id=str(user.id), email=user.email, name=user.name
    )
    headers = {'Authorization': f'Bearer {token}'}

    response = client.delete('/me/identities/google', headers=headers)
    assert response.status_code == HTTPStatus.NO_CONTENT

    # Confirmação no GET /me
    me_resp = client.get('/me', headers=headers)
    assert len(me_resp.json()['identities']) == 0


async def test_desvincular_identidade_recusado_se_for_unico_metodo_de_login(
    client: TestClient, user_generator, identity_generator
):
    """Regra de Proteção: Usuário sem senha não pode remover sua única identidade restante."""
    social_user = await user_generator(password=None)
    await identity_generator(
        social_user, provider='orcid', provider_user_id='orcid_999'
    )

    token = create_access_token(
        user_id=str(social_user.id),
        email=social_user.email,
        name=social_user.name,
    )
    headers = {'Authorization': f'Bearer {token}'}

    response = client.delete('/me/identities/orcid', headers=headers)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'único método de autenticação' in response.json()['detail']


async def test_usuario_sem_senha_com_duas_identidades_pode_remover_uma(
    client: TestClient, user_generator, identity_generator
):
    """Regra de Proteção: Usuário sem senha com duas identidades pode remover uma delas."""
    social_user = await user_generator(password=None)
    await identity_generator(
        social_user, provider='google', provider_user_id='g_1'
    )
    await identity_generator(
        social_user, provider='orcid', provider_user_id='o_2'
    )

    token = create_access_token(
        user_id=str(social_user.id),
        email=social_user.email,
        name=social_user.name,
    )
    headers = {'Authorization': f'Bearer {token}'}

    # Remove uma
    del_resp = client.delete('/me/identities/orcid', headers=headers)
    assert del_resp.status_code == HTTPStatus.NO_CONTENT

    # Tentativa de remover a segunda (última restante) deve falhar
    del_last = client.delete('/me/identities/google', headers=headers)
    assert del_last.status_code == HTTPStatus.BAD_REQUEST
    assert 'único método de autenticação' in del_last.json()['detail']
