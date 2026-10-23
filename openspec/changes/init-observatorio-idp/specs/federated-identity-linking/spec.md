# Federated Identity Linking Specification

## Purpose
Permitir a autenticação federada com provedores externos (Google e ORCID) e vinculação segura de identidades múltiplas à mesma conta de usuário ("Contas Conectadas"), garantindo prevenção contra sequestro de contas através de verificação estrita de e-mail.

## Requirements

### Requirement: Regras de Vinculação Federada
Ao receber o retorno de um provedor externo (`/auth/{provider}/callback`):
- Caso a tupla `(provider, provider_user_id)` já conste na base, o usuário associado é autenticado imediatamente.
- Caso não exista e o e-mail retornado coincida com um usuário existente:
  - Se o provedor garantir a verificação do e-mail (`email_verified == True`, caso do Google), a nova identidade é vinculada automaticamente à conta do usuário.
  - Se o provedor não garantir a verificação do e-mail (caso do ORCID), a vinculação automática é terminantemente proibida. O sistema deve recusar o vínculo automático e solicitar que o usuário realize login com sua conta existente para vinculação autenticada.
- Caso a identidade não exista e o e-mail não pertença a nenhum usuário, uma nova conta de usuário é criada sem senha com a respectiva identidade vinculada.

### Requirement: Gerenciamento de Contas Conectadas
O usuário logado pode consultar e gerenciar suas identidades através das rotas `/me`:
- `GET /me`: Retorna os dados da conta, indicando se possui senha e a lista de identidades conectadas.
- `POST /me/identities/{provider}`: Inicia o fluxo de autorização para conectar um novo provedor à sessão ativa.
- `DELETE /me/identities/{provider}`: Remove a identidade especificada.
- **Proteção de Acesso**: A remoção é recusada se for o único método restante de autenticação do usuário (sem senha e sem nenhuma outra identidade externa).
