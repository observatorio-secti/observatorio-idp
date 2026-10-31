# Design: Centralized Login UI, User Roles and PKCE Flow

## Context

O IdP já implementa OAuth 2.0 com PKCE e rotação de refresh tokens. No entanto, o endpoint `GET /authorize` exigia previamente uma sessão ou token Bearer já existente, levantando 401 caso o usuário não estivesse autenticado. Além disso, os tokens emitidos não carregavam o papel (`role`) do usuário, obrigando backends satélites a manterem suas próprias tabelas de usuário.

## Decisions

1. **Papel no Modelo User**:
   - `role`: string com valor `'DEFAULT'` ou `'ADMIN'`, indexada ou com default `'DEFAULT'`.
   - Adicionada ao JWT como claim padrão `"role"`. Desta forma, microsserviços satélites leem `payload["role"]` diretamente sem consultar bancos de dados.

2. **Fluxo Interativo no `GET /authorize`**:
   - Quando `GET /authorize` é invocado por um navegador (ou sem credencial ativa), em vez de retornar HTTP 401 JSON, o endpoint renderiza a página HTML de login (`templates/login.html`).
   - A página contém os campos ocultos de PKCE (`client_id`, `redirect_uri`, `code_challenge`, `code_challenge_method`, `state`).
   - Ao submeter o formulário (seja login ou cadastro), uma chamada de autenticação interna é realizada e o IdP gera o `authorization_code` chamando `TokenService.create_authorization_code(...)`, redirecionando com 302 para `redirect_uri?code=...&state=...`.

3. **Design System & Estética**:
   - A página HTML utiliza Tailwind CSS e a paleta definida no `observatorio-front/DESIGN.md`:
     - Fundo: `#f8f9fb`
     - Superfície do container de login: `#ffffff` com borda sutil `#e5e7eb` e sombra difusa
     - Acento da marca: Barra superior e botões em `#559FB8` (com hover `#024A60`)
     - Tipografia: Fonte `Lexend` importada do Google Fonts
     - Destaque textual CT&I Bahia: Gradiente `from-blue-700 to-red-600`
     - Botões sociais com ícones SVG oficiais de Google e ORCID.

4. **Preservação de Contexto PKCE no Login Social**:
   - Para login via Google ou ORCID, os parâmetros PKCE são serializados no parâmetro `state` do provedor OAuth externo (ou guardados em sessão/cookie temporário seguro).
   - Ao retornar em `/auth/{provider}/callback`, se houver contexto PKCE, o IdP emite o `authorization_code` e redireciona para a `redirect_uri` da aplicação requisitante.
