"""IdP publicado atrás de proxy reverso em um subcaminho (`/idp`).

Jornada: a pessoa entra no portal em produção e faz login no IdP.

Atores:
- Pessoa usuária do Observatório, com conta local já cadastrada.

Estado inicial: o nginx publica o IdP em `https://<portal>/idp/` e repassa
para o uvicorn com `--root-path /idp`. Tudo fora de `/idp/` é servido pelo
front estático, que não aceita POST (responde 405).

Passos:
1. A pessoa é levada a `/idp/authorize?...`. Espera ver a tela de login, e o
   formulário, os logos e os botões Google/ORCID apontam para `/idp/...`.
2. O navegador carrega os logos da tela. Espera ver as imagens.
3. A pessoa preenche e-mail e senha e envia o formulário para o endereço do
   `action`. Espera voltar ao callback do portal com `code` e `state`.

Desvios (testados à parte):
- Senha incorreta: a tela é reexibida e o novo envio continua em `/idp/`.
- Sem proxy (desenvolvimento local): os caminhos continuam na raiz.
"""

import re
from http import HTTPStatus
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from tests.test_oauth import _generate_pkce_pair

PREFIX = '/idp/'


def _form_action(html: str) -> str:
    match = re.search(r'<form id="auth-form"[^>]*action="([^"]*)"', html)
    assert match, 'formulário de autenticação não encontrado na página'
    return match.group(1)


def _local_urls(html: str, attribute: str) -> list[str]:
    """URLs do próprio host (iniciadas por `/`) em `src` ou `href`."""
    return re.findall(rf'{attribute}="(/[^"]*)"', html)


def _authorize_params(application, state: str = 'estado_csrf') -> dict:
    _, challenge = _generate_pkce_pair()
    return {
        'client_id': application.client_id,
        'redirect_uri': application.redirect_uris[0],
        'response_type': 'code',
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
        'state': state,
    }


def _login_form(params: dict, email: str, password: str) -> dict:
    return {**params, 'email': email, 'password': password, 'action': 'login'}


def test_usuario_faz_login_no_idp_publicado_em_subcaminho_e_volta_com_code(
    proxied_client: TestClient, application, user
):
    params = _authorize_params(application)

    # 1. A pessoa abre a tela de login pelo endereço público do IdP
    page = proxied_client.get(
        '/idp/authorize', params=params, headers={'Accept': 'text/html'}
    )
    assert page.status_code == HTTPStatus.OK
    assert 'text/html' in page.headers['content-type']

    action = _form_action(page.text)
    images = _local_urls(page.text, 'src')
    links = _local_urls(page.text, 'href')
    assert action == '/idp/authorize'
    assert len(images) == 2  # noqa: PLR2004 - brasão do governo e logo
    assert all(url.startswith(PREFIX) for url in images + links), (
        images + links
    )
    assert any(url.startswith('/idp/auth/google/login') for url in links)
    assert any(url.startswith('/idp/auth/orcid/login') for url in links)

    # 2. O navegador carrega os logos da tela
    for image in images:
        resp = proxied_client.get(image)
        assert resp.status_code == HTTPStatus.OK, image
        assert resp.headers['content-type'].startswith('image/')

    # 3. A pessoa envia e-mail e senha para o endereço do formulário
    resp = proxied_client.post(
        action,
        data=_login_form(params, user.email, user.raw_password),
        follow_redirects=False,
    )
    assert resp.status_code == HTTPStatus.SEE_OTHER
    location = resp.headers['location']
    assert location.startswith(params['redirect_uri'])
    callback = parse_qs(urlparse(location).query)
    assert callback['code']
    assert callback['state'] == [params['state']]


def test_senha_incorreta_atras_do_proxy_reexibe_formulario_no_subcaminho(
    proxied_client: TestClient, application, user
):
    params = _authorize_params(application)

    resp = proxied_client.post(
        '/idp/authorize',
        data=_login_form(params, user.email, 'senha-errada'),
    )

    assert resp.status_code == HTTPStatus.BAD_REQUEST
    assert 'text/html' in resp.headers['content-type']
    assert _form_action(resp.text) == '/idp/authorize'
    assert all(
        url.startswith(PREFIX)
        for url in _local_urls(resp.text, 'src')
        + _local_urls(resp.text, 'href')
    )


def test_sem_proxy_tela_de_login_usa_caminhos_na_raiz(
    client: TestClient, application
):
    resp = client.get(
        '/authorize',
        params=_authorize_params(application),
        headers={'Accept': 'text/html'},
    )

    assert resp.status_code == HTTPStatus.OK
    assert _form_action(resp.text) == '/authorize'
    assert '/static/images/LOGO.png' in _local_urls(resp.text, 'src')
    assert not any(
        url.startswith(PREFIX) for url in _local_urls(resp.text, 'href')
    )


def test_proxy_via_x_forwarded_prefix_header(client: TestClient, application):
    """Garante suporte a proxies que repassam apenas o header X-Forwarded-Prefix."""
    resp = client.get(
        '/authorize',
        params=_authorize_params(application),
        headers={'Accept': 'text/html', 'X-Forwarded-Prefix': '/idp'},
    )

    assert resp.status_code == HTTPStatus.OK
    assert _form_action(resp.text) == '/idp/authorize'
    assert all(
        url.startswith(PREFIX)
        for url in _local_urls(resp.text, 'src')
        + _local_urls(resp.text, 'href')
    )
