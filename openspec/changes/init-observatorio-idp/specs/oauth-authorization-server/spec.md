# OAuth Authorization Server Specification

## Purpose
Prover um servidor de autorização em conformidade com o padrão OAuth 2.0 / OIDC para as aplicações do ecossistema Observatório, utilizando o fluxo Authorization Code com PKCE e tokens JWT RS256 com chave pública distribuída via JWKS.

## Requirements

### Requirement: Fluxo de Autorização com PKCE
O endpoint `GET /authorize` deve orquestrar a autorização de clientes cadastrados.
- Parâmetros obrigatórios: `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`.
- O `client_id` deve corresponder a uma aplicação ativa cadastrada.
- O `redirect_uri` deve constar na lista de URIs autorizadas da aplicação; se não corresponder, o IdP deve rejeitar a requisição imediatamente sem efetuar redirecionamento.
- O código gerado (`code`) deve ter curta validade (5 minutos), ser de uso único e armazenado unicamente sob forma de hash criptográfico.

### Requirement: Troca de Código e Validação PKCE
O endpoint `POST /token` com `grant_type=authorization_code` deve validar o código e o verificador PKCE.
- Para método `S256`, valida `code_challenge == base64url(sha256(code_verifier))`.
- O código é marcado como utilizado imediatamente.
- Se a validação for bem-sucedida, o IdP emite um `access_token` JWT assinado com RS256 e um `refresh_token` opaco.

### Requirement: Rotação de Refresh Token e Família
O endpoint `POST /token` com `grant_type=refresh_token` deve suportar rotação contínua de refresh tokens.
- A cada uso, o token anterior é marcado como utilizado (`used_at = now()`) e um novo token é emitido associado ao mesmo `family_id`.
- Se um token já marcado como `used_at` for apresentado novamente (tentativa de reúso de token antigo), o IdP revoga toda a família (`revoked_at = now()`) e recusa a operação.

### Requirement: Distribuição de Chaves Públicas (JWKS)
O endpoint `GET /.well-known/jwks.json` deve disponibilizar as chaves públicas ativas no formato padrão JWKS (RFC 7517) contendo os parâmetros `kty`, `use`, `alg`, `kid`, `n` e `e`.
- Aplicações satélites (como `simcc-admin`) validam localmente as assinaturas dos tokens RS256 consultando o JWKS com cache.
