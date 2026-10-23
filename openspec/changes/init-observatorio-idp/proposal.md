# Proposal: Inicialização do observatorio-idp

## Why

O ecossistema Observatório (Observatório, VIP, Simcc Admin, Simcc Back, Maria, Fomento) precisa de um serviço central de identidade (IdP) unificado. O princípio orientador é: o IdP responde somente a **"quem é essa pessoa?"**, enquanto **"o que ela pode fazer?"** permanece sob a responsabilidade de cada aplicação consumidora através do claim `sub` (user_id).

Dessa forma:
- O IdP não armazena papéis (RBAC) nem dados acadêmicos específicos (como Lattes ID ou filiação institucional, que continuam no `simcc-admin`).
- Os backends validam localmente os tokens de acesso via JWKS público (`/.well-known/jwks.json`), sem gargalo de rede por requisição.
- Oferece suporte a login local (Argon2), provedores externos (Google e ORCID) e vinculação de múltiplas identidades à mesma conta ("contas conectadas"), evitando sequestro de conta através de regras estritas de verificação de e-mail.

## What Changes

1. **Modelos de Dados e Persistência**:
   - Modelos SQLAlchemy 2.0 assíncronos: `User`, `Identity`, `Application`, `RefreshToken`, `AuthorizationCode`.
   - Suporte a migrações com Alembic e persistência compatível com PostgreSQL e SQLite assíncrono.
2. **Criptografia e Chaves**:
   - Chaves assimétricas RSA (RS256) carregadas de variável de ambiente ou geradas sob demanda com `kid`.
   - Endpoint público JWKS (`/.well-known/jwks.json`) para distribuição de chaves públicas.
   - Hash seguro de senhas com Argon2 (`pwdlib[argon2]`).
3. **Fluxo OAuth2 / OIDC**:
   - Fluxo Authorization Code com PKCE (S256 / plain) em `/authorize` e `/token`.
   - Access token JWT assinado (RS256, 15 min) contendo `sub`, `email`, `name`, `iss`, `aud`, `iat`, `exp`, `jti`.
   - Refresh token opaco com rotação automática e revogação por detecção de reuso da família (`family_id`).
4. **Login Local e Provedores Federados**:
   - Cadastro e login local (`/auth/register`, `/auth/login`).
   - Integração OAuth com Google e ORCID via Authlib (`/auth/{provider}/login`, `/auth/{provider}/callback`).
   - Regras de vinculação: Google com e-mail verificado associa à conta existente; ORCID (e-mail não verificado) exige login prévio e vinculação manual.
   - Gestão de contas conectadas (`/me`, `POST /me/identities/{provider}`, `DELETE /me/identities/{provider}`), garantindo que o usuário nunca remova seu último método de autenticação.
5. **Configurações e Boas Práticas**:
   - Pydantic Settings para variáveis de ambiente.
   - Testes assíncronos com pytest, pytest-asyncio e factories (FactoryBoy).

## Capabilities

### New Capabilities

- `local-authentication`: Cadastro local, validação de credenciais, hash de senhas com Argon2 e sessão de usuário.
- `oauth-authorization-server`: Servidor de autorização OAuth2 com PKCE, emissão de tokens JWT RS256, rotação de refresh tokens e exposição de JWKS.
- `federated-identity-linking`: Autenticação externa via Google e ORCID, regras estritas de associação de identidades e gerenciamento de contas conectadas.

### Modified Capabilities

Nenhuma (repositório inicial).

## Impact

- Criação da base de código do serviço `observatorio-idp`.
- Disponibilização de chaves JWKS para validação desacoplada em backends satélites (como `simcc-admin`).
- Arquitetura limpa preparada para compose e ambientes de produção.
