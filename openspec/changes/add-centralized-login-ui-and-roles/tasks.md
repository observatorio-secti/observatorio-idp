# Tasks: Centralized Login UI, User Roles and PKCE Flow

## 1. Modelo e Migração Alembic
- [x] 1.1 Adicionar campo `role` ao modelo `User` em `app/models/user.py` com valor padrão `'DEFAULT'`.
- [x] 1.2 Atualizar schemas `UserPublic` e afins em `app/schemas/user.py`.
- [x] 1.3 Criar e aplicar migração Alembic para adicionar a coluna `role` na tabela `users`.
- [x] 1.4 Adicionar configuração de bootstrap de administrador em `app/core/config.py` e semeadura automática se não existir.

## 2. Emissão de Claims e Tokens
- [x] 2.1 Adicionar claim `"role"` em `app/core/keys.py` (`create_access_token`).
- [x] 2.2 Propagar `role` na geração de tokens em `TokenService` e `routers/auth.py`.

## 3. Interface Centralizada de Login e Fluxo PKCE
- [x] 3.1 Criar template `app/templates/login.html` com estética *Simcc Intelligence* (`Lexend`, `#559FB8`, `#024A60`, suporte a login local e botões Google/ORCID).
- [x] 3.2 Atualizar `app/routers/authorize.py` para renderizar o template HTML quando acessado sem usuário autenticado e processar POST do formulário emitindo authorization code.
- [x] 3.3 Integrar o fluxo social (`routers/oauth_providers.py`) para transportar os parâmetros PKCE e redirecionar para a aplicação cliente com authorization code.
- [x] 3.4 Atualizar `seed_default_applications` em `app/services/application_service.py` com as URIs autorizadas de desenvolvimento e produção.

## 4. Testes e Validação
- [x] 4.1 Atualizar suíte de testes de `observatorio-idp` cobrindo a nova claim `role`, tela de login e fluxo PKCE.
- [x] 4.2 Executar testes automatizados do IdP e garantir 100% de sucesso.
