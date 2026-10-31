# Tasks: Implementação do observatorio-idp

## 1. Base do Projeto, Configuração e Banco Assíncrono

- [x] 1.1 Configurar `Settings` com `pydantic-settings` no `app/core/config.py` (URLs de banco, segredos, credenciais OAuth, tempos de expiração)
- [x] 1.2 Configurar engine e sessionmaker assíncronos do SQLAlchemy em `app/core/database.py` com dependência `get_session`
- [x] 1.3 Criar modelos SQLAlchemy em `app/models/` (`User`, `Identity`, `Application`, `RefreshToken`, `AuthorizationCode`)
- [x] 1.4 Configurar Alembic com ambiente assíncrono para PostgreSQL e SQLite

## 2. Segurança, Chaves RSA, JWT e JWKS

- [x] 2.1 Implementar hash e verificação Argon2 em `app/core/security.py`
- [x] 2.2 Implementar gerenciador de chaves RSA e assinatura de JWT RS256 com `kid` em `app/core/keys.py`
- [x] 2.3 Implementar endpoint público `GET /.well-known/jwks.json` no router `app/routers/jwks.py`

## 3. Autenticação Local e Sessão

- [x] 3.1 Implementar schemas de usuário e autenticação em `app/schemas/auth.py` e `app/schemas/user.py`
- [x] 3.2 Implementar lógica de cadastro e login local em `app/services/account_service.py`
- [x] 3.3 Implementar endpoints `POST /auth/register`, `POST /auth/login` e `POST /logout` em `app/routers/auth.py`

## 4. Servidor OAuth2: Authorization Code + PKCE e Rotação de Tokens

- [x] 4.1 Implementar validação de aplicações clientes e seed inicial de aplicações em `app/services/application_service.py`
- [x] 4.2 Implementar geração de Authorization Code, validação PKCE (S256 / plain), emissão de tokens e rotação com detecção de reuso da família em `app/services/token_service.py`
- [x] 4.3 Implementar rotas `GET /authorize` e `POST /token` em `app/routers/authorize.py`

## 5. Provedores Federados (Google e ORCID) e Vinculação de Contas

- [x] 5.1 Configurar clientes OAuth com Authlib e endpoints `/auth/{provider}/login` e `/auth/{provider}/callback` em `app/routers/oauth_providers.py`
- [x] 5.2 Implementar regras estritas de vinculação por e-mail verificado vs não-verificado em `app/services/account_service.py`
- [x] 5.3 Implementar rotas de perfil e contas conectadas (`GET /me`, `POST /me/identities/{provider}`, `DELETE /me/identities/{provider}`) em `app/routers/me.py`

## 6. Docker Compose, Integração e Testes Automatizados

- [x] 6.1 Criar `compose.yaml` e `Dockerfile` do `observatorio-idp` para execução integrada
- [x] 6.2 Criar factories com FactoryBoy e fixtures em `tests/conftest.py`
- [x] 6.3 Implementar testes de cadastro e login local (`tests/test_auth.py`)
- [x] 6.4 Implementar testes de OAuth2, PKCE, rotação de refresh token e JWKS (`tests/test_oauth.py`)
- [x] 6.5 Implementar testes de vinculação federada e gerenciamento de identidades (`tests/test_linking.py` e `tests/test_me.py`)
- [x] 6.6 Validar execução de toda a suíte de testes com cobertura e verificar qualidade com linter
