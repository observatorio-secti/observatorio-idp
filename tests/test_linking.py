from http import HTTPStatus
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.keys import key_manager
from app.models.identity import Identity
from app.oauth.base import OAuthUserInfo


def test_login_redirect_google(client: TestClient):
    """Regra: /auth/google/login redireciona para accounts.google.com."""
    response = client.get('/auth/google/login', follow_redirects=False)
    assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    assert 'accounts.google.com' in response.headers['location']


def test_login_redirect_orcid(client: TestClient):
    """Regra: /auth/orcid/login redireciona para sandbox.orcid.org."""
    response = client.get('/auth/orcid/login', follow_redirects=False)
    assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
    assert 'orcid.org' in response.headers['location']


def test_login_provedor_desconhecido_retorna_404(client: TestClient):
    """Regra: Provedor não suportado retorna 404 Not Found."""
    response = client.get('/auth/facebook/login')
    assert response.status_code == HTTPStatus.NOT_FOUND


def test_callback_novo_usuario_google_cria_conta_sem_senha(
    client: TestClient, session: AsyncSession
):
    """Jornada: Novo usuário autentica via Google. O IdP cria a conta sem senha e vincula a identidade."""
    mock_info = OAuthUserInfo(
        provider='google',
        provider_user_id='google_sub_9999',
        email='novo.pesquisador@gmail.com',
        name='Pesquisador Novo',
        email_verified=True,
    )

    with patch(
        'app.oauth.google.GoogleOAuthProvider.get_user_info',
        new_callable=AsyncMock,
        return_value=mock_info,
    ):
        response = client.get(
            '/auth/google/callback?code=mock_code&state=mock_state',
            follow_redirects=False,
        )
        assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
        location = response.headers['location']
        params = parse_qs(urlparse(location).query)
        assert 'token' in params
        token = params['token'][0]

        claims = key_manager.decode_jwt(token)
        assert claims['email'] == 'novo.pesquisador@gmail.com'
        assert claims['name'] == 'Pesquisador Novo'


async def test_callback_google_email_existente_vincula_automaticamente(
    client: TestClient, session: AsyncSession, user
):
    """Regra de Segurança: Como o Google garante e-mail verificado, ele pode vincular à conta existente."""
    mock_info = OAuthUserInfo(
        provider='google',
        provider_user_id='google_sub_existing_123',
        email=user.email,
        name='Nome Google',
        email_verified=True,
    )

    with patch(
        'app.oauth.google.GoogleOAuthProvider.get_user_info',
        new_callable=AsyncMock,
        return_value=mock_info,
    ):
        response = client.get(
            '/auth/google/callback?code=mock_code',
            follow_redirects=False,
        )
        assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
        params = parse_qs(urlparse(response.headers['location']).query)
        token = params['token'][0]
        claims = key_manager.decode_jwt(token)
        assert claims['sub'] == str(user.id)

        # Confirma que a identidade foi salva associada ao user.id
        identities = (
            await session.scalars(
                select(Identity).where(Identity.user_id == user.id)
            )
        ).all()
        assert any(
            i.provider == 'google'
            and i.provider_user_id == 'google_sub_existing_123'
            for i in identities
        )


def test_callback_orcid_email_existente_recusa_vinculo_automatico(
    client: TestClient, user
):
    """Regra Crítica de Anti-sequestro: O ORCID não garante verificação do e-mail.
    O IdP deve RECUSAR vínculo automático quando o e-mail coincide com uma conta existente.
    """
    mock_info = OAuthUserInfo(
        provider='orcid',
        provider_user_id='0000-0002-1825-0097',
        email=user.email,
        name='Pesquisador ORCID',
        email_verified=False,
    )

    with patch(
        'app.oauth.orcid.OrcidOAuthProvider.get_user_info',
        new_callable=AsyncMock,
        return_value=mock_info,
    ):
        response = client.get(
            '/auth/orcid/callback?code=mock_code', follow_redirects=False
        )
        assert response.status_code == HTTPStatus.CONFLICT
        assert 'bloqueado por segurança' in response.json()['detail']


def test_callback_orcid_novo_usuario_sem_email_cria_conta_sintetica(
    client: TestClient,
):
    """Jornada: Usuário conecta com ORCID sem divulgar e-mail público.
    O IdP gera uma conta com e-mail sintético e identidade vinculada.
    """
    mock_info = OAuthUserInfo(
        provider='orcid',
        provider_user_id='0000-0003-9999-1111',
        email=None,
        name='Dr. Cientista',
        email_verified=False,
    )

    with patch(
        'app.oauth.orcid.OrcidOAuthProvider.get_user_info',
        new_callable=AsyncMock,
        return_value=mock_info,
    ):
        response = client.get(
            '/auth/orcid/callback?code=mock_code', follow_redirects=False
        )
        assert response.status_code == HTTPStatus.TEMPORARY_REDIRECT
        params = parse_qs(urlparse(response.headers['location']).query)
        token = params['token'][0]
        claims = key_manager.decode_jwt(token)
        assert '0000-0003-9999-1111' in claims['email']
        assert claims['name'] == 'Dr. Cientista'
