# Proposal: Centralized Login UI, User Roles and PKCE Flow

## Why

Atualmente, o ecossistema Observatório necessita de um fluxo de autenticação centralizado (SSO) para eliminar formulários locais de login nos módulos satélites (como o `simcc-front` e o portal institucional `observatorio-front`). Para que o `simcc-admin` e outras aplicações satélites possam delegar 100% do controle de acesso ao IdP de forma *stateless*, o `observatorio-idp` precisa emitir papéis de usuário (`role`: `DEFAULT` | `ADMIN`) em seus tokens JWT RS256 e no endpoint `/me`, além de fornecer uma interface visual de login (`/authorize` / `/login`) alinhada com a identidade visual do Observatório (`observatorio-front/DESIGN.md`).

## What Changes

1. **Papel de Usuário (`role`) no IdP**:
   - Adicionar campo `role` (`DEFAULT` e `ADMIN`, padrão `DEFAULT`) no modelo `User` do IdP com migração Alembic.
   - Incluir a claim `role` no payload dos access tokens JWT RS256 e no schema `UserPublic` retornado por `GET /me`.
   - Suporte a variáveis de ambiente para inicialização de administrador (`ADMIN_EMAIL`, `ADMIN_NAME`, `ADMIN_PASSWORD`).

2. **Interface Centralizada de Autenticação (`/authorize` e `/login`)**:
   - Renderizar página HTML moderna responsiva (seguindo a estética *Simcc Intelligence* do `observatorio-front`: tipografia Lexend, cores institucionais SECTI Bahia, botões para Google, ORCID e formulário de e-mail/senha).
   - Suportar login e cadastro diretamente na tela do IdP preservando o fluxo PKCE (`client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`, `state`).
   - Redirecionar para `redirect_uri?code=...&state=...` após autenticação bem-sucedida.

3. **Integração PKCE com Login Federado (Google / ORCID)**:
   - Permitir que os endpoints `/auth/{provider}/login` e `/auth/{provider}/callback` preservem os parâmetros PKCE do cliente, gerando o authorization code correspondente no retorno do provedor social.

4. **Registro de Clientes Padrão**:
   - Atualizar `seed_default_applications` com as URIs de desenvolvimento e produção do `simcc` e `observatorio`.

## Capabilities

### Modified Capabilities
- `oauth-authorization-server`: Suporte a exibição interativa da tela de login e claims de papel (`role`) no token RS256.
- `local-authentication`: Retorno de `role` no cadastro, login e perfil.
- `federated-identity-linking`: Suporte a transporte de parâmetros de autorização PKCE.

## Impact
- `app/models/user.py`: Nova coluna `role`.
- `app/schemas/user.py`: Campo `role` no schema de resposta.
- `app/core/keys.py`: Adição de `role` nas claims do token JWT.
- `app/routers/authorize.py`: Renderização da interface web de login para requisições interativas.
- `app/templates/login.html`: Template visual de autenticação institucional.
- `migrations/versions/`: Nova revisão Alembic adicionando coluna `role`.
