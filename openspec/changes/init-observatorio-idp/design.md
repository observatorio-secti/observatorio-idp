# Design: Arquitetura do observatorio-idp

## 1. Visão Geral e Princípios de Arquitetura

O `observatorio-idp` é estruturado em camadas desacopladas seguindo o padrão de routers finos, serviços de domínio ricos e modelos SQLAlchemy 2.0 assíncronos:

```
app/
├── core/
│   ├── config.py       # Pydantic Settings
│   ├── database.py     # Engine assíncrono e sessionmaker
│   ├── security.py     # Hash Argon2 e utilitários de segurança
│   └── keys.py         # Chaves RSA, assinatura RS256 e JWKS
├── models/
│   ├── base.py         # DeclarativeBase e mixins comuns
│   ├── user.py         # Modelo User
│   ├── identity.py     # Modelo Identity (Google, ORCID)
│   ├── application.py  # Modelo Application (OAuth clients)
│   └── token.py        # RefreshToken e AuthorizationCode
├── schemas/
│   ├── auth.py         # Schemas de registro, login e sessão
│   ├── oauth.py        # Schemas de authorize, token e jwks
│   ├── identity.py     # Schemas de identidades conectadas
│   └── user.py         # Schemas de perfil e dados públicos
├── services/
│   ├── account_service.py      # Criação de conta, login local e vinculação
│   ├── token_service.py        # Emissão JWT, rotação de refresh e PKCE
│   └── application_service.py  # Validação de clientes e redirect URIs
├── routers/
│   ├── auth.py                 # /auth/register, /auth/login, /logout
│   ├── authorize.py            # /authorize, /token
│   ├── oauth_providers.py      # /auth/{provider}/login, /callback
│   ├── me.py                   # /me, /me/identities/{provider}
│   └── jwks.py                 # /.well-known/jwks.json
└── main.py                     # Configuração FastAPI, CORS, rotas e lifespan
```

## 2. Modelo de Dados

### Tabelas

- **users**:
  - `id`: UUID (Primary Key)
  - `email`: String (Unique, Indexed)
  - `name`: String
  - `password_hash`: String (Nullable - nulo para contas criadas exclusivamente via login social)
  - `is_active`: Boolean (Default: True)
  - `created_at`: DateTime (UTC)
  - `updated_at`: DateTime (UTC)

- **identities**:
  - `id`: UUID (Primary Key)
  - `user_id`: UUID (Foreign Key para `users.id`, onDelete CASCADE)
  - `provider`: String (`google` | `orcid`)
  - `provider_user_id`: String (Identificador no provedor)
  - `email`: String (Nullable)
  - `created_at`: DateTime (UTC)
  - **Constraint**: `UNIQUE(provider, provider_user_id)`

- **applications**:
  - `client_id`: String (Primary Key)
  - `client_secret`: String (Nullable - para clientes confidenciais)
  - `name`: String
  - `redirect_uris`: JSON/String list (URIs autorizadas)
  - `is_active`: Boolean (Default: True)
  - `created_at`: DateTime (UTC)

- **refresh_tokens**:
  - `id`: UUID (Primary Key)
  - `user_id`: UUID (Foreign Key para `users.id`, onDelete CASCADE)
  - `client_id`: String (Foreign Key para `applications.client_id`)
  - `token_hash`: String (Unique, SHA-256 do token opaco)
  - `family_id`: UUID (Agrupador da cadeia de rotação)
  - `expires_at`: DateTime (UTC)
  - `used_at`: DateTime (Nullable - marca quando foi rotacionado)
  - `revoked_at`: DateTime (Nullable - marca quando foi cancelado)
  - `created_at`: DateTime (UTC)

- **authorization_codes**:
  - `code_hash`: String (Primary Key / Unique, SHA-256 do código)
  - `client_id`: String (Foreign Key para `applications.client_id`)
  - `user_id`: UUID (Foreign Key para `users.id`)
  - `redirect_uri`: String
  - `code_challenge`: String
  - `code_challenge_method`: String (`S256` | `plain`)
  - `expires_at`: DateTime (UTC, validade de 5 minutos)
  - `used_at`: DateTime (Nullable - uso único)

## 3. Criptografia e Tokens

### Chave RSA e JWKS
- Chave privada RSA mantida em variável de ambiente `IDP_PRIVATE_KEY_PEM` ou gerada dinamicamente com 2048 bits se em desenvolvimento/teste.
- Cada chave tem um identificador único `kid` incluído no header do JWT (`kid=...`) e no conjunto JWKS.
- `GET /.well-known/jwks.json` expõe a chave pública codificada em Base64URL nos campos `n` e `e`.

### Access Token (JWT RS256)
- Duração: 15 minutos (900s).
- Claims:
  - `iss`: Configurado em `IDP_ISSUER` (ex.: `https://idp.observatorio.ba.gov.br`)
  - `sub`: UUID do usuário em formato string
  - `aud`: `client_id` da aplicação solicitante (ex.: `simcc`)
  - `email`: e-mail principal do usuário
  - `name`: nome completo
  - `iat`: timestamp de emissão
  - `exp`: timestamp de expiração
  - `jti`: identificador único aleatório

### Rotação de Refresh Token e Família
- Refresh tokens são strings aleatórias criptograficamente seguras (`secrets.token_urlsafe(32)`).
- Apenas seu hash SHA-256 é armazenado no banco de dados.
- Ao usar um refresh token válido:
  1. Marca o token atual com `used_at = now()`.
  2. Emite um novo refresh token com o mesmo `family_id`.
  3. Emite um novo access token JWT.
- **Detecção de Reúso**: Se uma requisição apresentar um refresh token cujo hash já possua `used_at` preenchido (ou seja, foi reutilizado após já ter sido rotacionado), o sistema marca **todos** os tokens com aquele `family_id` como revogados (`revoked_at = now()`) e recusa a requisição com erro `invalid_grant`.

### Validação PKCE
- Desafio de código com método `S256`:
  `code_challenge == base64url(sha256(code_verifier))`
- Também suporta `plain` (para clientes legados sem hash, onde `code_challenge == code_verifier`).

## 4. Matriz de Vinculação de Identidades Federadas

| Cenário de Callback | Ação do IdP |
|---|---|
| `(provider, provider_user_id)` já existe na tabela `identities` | Autentica diretamente o usuário associado |
| Não existe identity, mas o e-mail bate com um `user` existente e o provedor garante verificação (`email_verified == True`, Google) | Vincula automaticamente a nova `identity` à conta existente e autentica o usuário |
| Não existe identity, o e-mail bate com um `user` existente, mas o provedor **não** garante verificação (ORCID) | **Recusa** a vinculação automática por risco de sequestro. Exige login na conta existente para vinculação autenticada |
| Não existe identity e nenhum usuário possui esse e-mail | Cria novo `user` (sem senha) e a respectiva `identity` vinculada |

### Gerenciamento de Identidades Autenticado
- `GET /me`: Retorna perfil, se tem senha definida (`has_password: bool`) e lista de provedores vinculados.
- `POST /me/identities/{provider}`: Inicia o fluxo de autorização com o provedor para anexar a identidade à conta logada.
- `DELETE /me/identities/{provider}`: Remove a identidade. Se o usuário não tiver senha cadastrada e essa for sua única identidade externa, a operação é rejeitada com HTTP 400 (impedindo que a conta fique inacessível).
