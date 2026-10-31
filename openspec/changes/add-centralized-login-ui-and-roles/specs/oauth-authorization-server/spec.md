# Spec Delta: OAuth Authorization Server

## Requirements

### Requirement: Role Claim no Access Token JWT
O token JWT RS256 emitido pelo IdP SHALL conter a claim `role` correspondente ao papel do usuário (`DEFAULT` ou `ADMIN`).

#### Scenario: Emissão de token com papel
- **WHEN** um usuário autenticado com papel `ADMIN` obtém um token via `POST /token`
- **THEN** o payload do token JWT decodificado contém `"role": "ADMIN"`

### Requirement: Exibição Interativa do Formulário de Autorização
Quando uma requisição `GET /authorize` for efetuada sem sessão autenticada, o IdP SHALL renderizar a página HTML de autenticação preservando os parâmetros PKCE.

#### Scenario: Acesso sem autenticação prévia
- **WHEN** um cliente acessa `GET /authorize` com `client_id`, `redirect_uri`, `response_type=code`, `code_challenge`
- **THEN** a resposta é HTTP 200 com `Content-Type: text/html` contendo os campos de login e os parâmetros PKCE embutidos
