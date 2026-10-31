from http import HTTPStatus

from fastapi.testclient import TestClient

from app.core.keys import key_manager


def test_jornada_cadastro_e_login_local_com_sucesso(client: TestClient):
    """Jornada: Novo usuário se cadastra com e-mail e senha, e efetua login obtendo token JWT RS256."""
    # 1. Cadastro
    register_payload = {
        'email': 'ana.silva@observatorio.ba.gov.br',
        'name': 'Ana Silva',
        'password': 'senhaForteSegura123!',
    }
    reg_response = client.post('/auth/register', json=register_payload)
    assert reg_response.status_code == HTTPStatus.CREATED
    data = reg_response.json()
    assert data['email'] == 'ana.silva@observatorio.ba.gov.br'
    assert data['name'] == 'Ana Silva'
    assert data['has_password'] is True
    assert data['is_active'] is True
    assert 'id' in data

    # 2. Login com as credenciais cadastradas
    login_payload = {
        'email': 'ana.silva@observatorio.ba.gov.br',
        'password': 'senhaForteSegura123!',
    }
    login_response = client.post('/auth/login', json=login_payload)
    assert login_response.status_code == HTTPStatus.OK
    token_data = login_response.json()
    assert 'access_token' in token_data
    assert token_data['token_type'] == 'bearer'
    assert token_data['expires_in'] == 900

    # 3. Validação da assinatura do token JWT emitido (RS256)
    access_token = token_data['access_token']
    payload = key_manager.decode_jwt(access_token)
    assert payload['email'] == 'ana.silva@observatorio.ba.gov.br'
    assert payload['name'] == 'Ana Silva'
    assert payload['sub'] == data['id']


def test_cadastro_email_duplicado_retorna_conflito(client: TestClient, user):
    """Regra: Não é permitido cadastrar o mesmo e-mail duas vezes."""
    payload = {
        'email': user.email,
        'name': 'Outro Nome',
        'password': 'outrasenha123',
    }
    response = client.post('/auth/register', json=payload)
    assert response.status_code == HTTPStatus.CONFLICT
    assert 'já cadastrado' in response.json()['detail']


def test_login_senha_incorreta_retorna_credenciais_invalidas(
    client: TestClient, user
):
    """Regra: Senha incorreta deve responder com mensagem genérica para mitigar enumeração."""
    payload = {
        'email': user.email,
        'password': 'senhaTotalmenteIncorreta999',
    }
    response = client.post('/auth/login', json=payload)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json()['detail'] == 'Credenciais inválidas.'


def test_login_email_inexistente_retorna_mesma_mensagem_generica(
    client: TestClient,
):
    """Regra: E-mail inexistente deve responder com a mesma mensagem de erro da senha incorreta."""
    payload = {
        'email': 'email_que_nao_existe_jamais@dominio.com',
        'password': 'qualquersenha123',
    }
    response = client.post('/auth/login', json=payload)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.json()['detail'] == 'Credenciais inválidas.'


async def test_login_conta_social_sem_senha_orienta_login_social(
    client: TestClient, user_generator
):
    """Regra: Conta criada via login social sem senha não pode efetuar login por senha."""
    social_user = await user_generator(password=None)
    payload = {
        'email': social_user.email,
        'password': 'tentativaDeSenha123',
    }
    response = client.post('/auth/login', json=payload)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert 'login social' in response.json()['detail']


def test_logout_retorna_no_content(client: TestClient):
    """Regra: Endpoint de logout encerra a sessão e retorna 204."""
    response = client.post('/auth/logout')
    assert response.status_code == HTTPStatus.NO_CONTENT
