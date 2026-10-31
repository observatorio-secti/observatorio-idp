# Guia de Integração com o Observatório IdP

Este documento orienta os desenvolvedores de **frontends (SPAs/Web)** e **backends satélites (ex.: simcc-admin, maria-api, fomento)** sobre como autenticar usuários e validar tokens emitidos pelo IdP central.

---

## 1. Princípio Fundamental de Arquitetura

- **O IdP responde**: *"Quem é essa pessoa?"* (`sub`, `email`, `name`).
- **A aplicação satélite responde**: *"O que essa pessoa pode fazer aqui?"* (papéis, permissões, dados institucionais).
- **Sem sobrecarga de rede**: Backends validam os tokens **localmente** utilizando chaves públicas distribuídas pelo endpoint JWKS do IdP com cache, sem fazer requisição HTTP por chamada autenticada.

---

## 2. Para Aplicações Frontend (SPAs / Next.js / Vue / React)

Aplicações de frontend utilizam o fluxo padrão **OAuth 2.0 Authorization Code com PKCE**.

### Passo 1: Gerar o Desafio PKCE
Gere uma string aleatória (`code_verifier`) de 43 a 128 caracteres e calcule seu hash SHA-256 codificado em Base64URL (`code_challenge`):

```typescript
// Exemplo em TypeScript / JavaScript no navegador:
function base64UrlEncode(arrayBuffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function generatePKCE() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = base64UrlEncode(array);

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const codeChallenge = base64UrlEncode(digest);

  // Armazene o code_verifier temporariamente (ex: sessionStorage)
  sessionStorage.setItem('pkce_verifier', codeVerifier);

  return { codeVerifier, codeChallenge };
}
```

### Passo 2: Redirecionar o Usuário para o IdP
Redirecione o usuário para a tela de autorização do IdP:

```
GET https://idp.observatorio.ba.gov.br/authorize?
  client_id=simcc&
  redirect_uri=https://simcc.observatorio.ba.gov.br/auth/callback&
  response_type=code&
  code_challenge={CODE_CHALLENGE}&
  code_challenge_method=S256&
  state={RANDOM_STATE}
```

> **Login Social Direto**: Se o usuário clicar em "Entrar com Google" ou "Entrar com ORCID", você pode redirecioná-lo diretamente para:
> - Google: `GET https://idp.observatorio.ba.gov.br/auth/google/login`
> - ORCID: `GET https://idp.observatorio.ba.gov.br/auth/orcid/login`

### Passo 3: Receber o Código e Trocar por Tokens
Na sua rota de callback (`/auth/callback`), capture o parâmetro `code` da URL e envie via POST para o IdP:

```http
POST https://idp.observatorio.ba.gov.br/token
Content-Type: application/json

{
  "grant_type": "authorization_code",
  "client_id": "simcc",
  "code": "{CODE_RECEBIDO}",
  "redirect_uri": "https://simcc.observatorio.ba.gov.br/auth/callback",
  "code_verifier": "{CODE_VERIFIER_DO_SESSION_STORAGE}"
}
```

**Resposta do IdP (HTTP 200 OK):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRlZmF1bHQta2lkI...",
  "token_type": "bearer",
  "expires_in": 900,
  "refresh_token": "uY7zB...token_opaco_seguro...",
  "scope": "openid profile email"
}
```

### Passo 4: Fazer Requisições Autenticadas às APIs Satélites
Envie o token no cabeçalho de todas as requisições:
```http
GET https://api.simcc.observatorio.ba.gov.br/pesquisadores
Authorization: Bearer {access_token}
```

### Passo 5: Rotação Contínua de Refresh Token
Quando o `access_token` expirar (a cada 15 minutos), utilize o `refresh_token` para renovar:

```http
POST https://idp.observatorio.ba.gov.br/token
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "client_id": "simcc",
  "refresh_token": "{REFRESH_TOKEN_ATUAL}"
}
```
*O IdP devolverá um novo `access_token` e um NOVO `refresh_token` (descarte o antigo).*

---

## 3. Para Backends Satélites (ex.: `simcc-admin`, `simcc-back`)

Os backends satélites **não consultam o IdP por requisição**. Eles validam os tokens RS256 **localmente** utilizando o conjunto de chaves públicas JWKS (`/.well-known/jwks.json`).

### Formato do Token Emitido pelo IdP
O token é assinado com algoritmo **RS256** e possui o cabeçalho:
```json
{
  "alg": "RS256",
  "kid": "default-kid"
}
```
E o payload:
```json
{
  "iss": "https://idp.observatorio.ba.gov.br",
  "sub": "a5c777d1-0422-4467-8b06-a88ba8c1a85b",
  "email": "pesquisador@ufba.br",
  "name": "Maria Santos",
  "aud": "simcc",
  "iat": 1729700000,
  "exp": 1729700900,
  "jti": "d6e3c15d-8547-4933-90d5-1c7b559ce911"
}
```

### Exemplo de Validação em Python / FastAPI (para `simcc-admin`)

No backend satélite, basta usar o `PyJWKClient` do `PyJWT` para validar com cache automático:

```python
# Em simcc_admin/security.py:
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt
from jwt import PyJWKClient

# URL pública do endpoint JWKS do IdP
IDP_JWKS_URL = "https://idp.observatorio.ba.gov.br/.well-known/jwks.json"
IDP_ISSUER = "https://idp.observatorio.ba.gov.br"
AUDIENCE = "simcc"  # client_id desta aplicação

jwks_client = PyJWKClient(IDP_JWKS_URL, cache_keys=True, max_cached_keys=16)
bearer_scheme = HTTPBearer(auto_error=True)

class AuthenticatedUser:
    def __init__(self, user_id: UUID, email: str, name: str, role: str):
        self.id = user_id
        self.email = email
        self.name = name
        self.role = role

async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    # session: AsyncSession = Depends(get_session) # para buscar papéis locais
) -> AuthenticatedUser:
    token = credentials.credentials
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=IDP_ISSUER,
            audience=AUDIENCE,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Token inválido, expirado ou emitido por servidor não confiável.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = UUID(payload["sub"])
    email = payload.get("email")
    name = payload.get("name")

    # Papéis e autorizações pertencem ao banco LOCAL do simcc-admin:
    # local_user = await session.get(User, user_id)
    # role = local_user.role if local_user else "DEFAULT"
    role = "ADMIN"  # obtido localmente via sub (user_id)

    return AuthenticatedUser(user_id=user_id, email=email, name=name, role=role)
```

---

## 4. Matriz de Endpoints do IdP

| Método | Endpoint | Descrição | Quem consome? |
|---|---|---|---|
| `GET` | `/.well-known/jwks.json` | Chaves públicas ativas (RFC 7517) | Backends satélites (com cache) |
| `GET` | `/authorize` | Início do fluxo PKCE (redirecionamento) | Frontend (navegador) |
| `POST` | `/token` | Troca de código PKCE e rotação de Refresh Token | Frontend / Aplicações |
| `POST` | `/auth/register` | Cadastro local com senha | Frontend |
| `POST` | `/auth/login` | Login direto com e-mail e senha | Frontend |
| `POST` | `/auth/logout` | Encerramento de sessão | Frontend |
| `GET` | `/auth/{provider}/login` | Início do fluxo federado (Google / ORCID) | Frontend (navegador) |
| `GET` | `/auth/{provider}/callback` | Retorno do provedor federado | Navegador (redireciona ao front) |
| `GET` | `/me` | Consulta perfil e identidades conectadas | Usuário autenticado |
| `POST` | `/me/identities/{provider}` | Conectar novo provedor social à conta ativa | Usuário autenticado |
| `DELETE`| `/me/identities/{provider}` | Desconectar provedor social da conta | Usuário autenticado |
