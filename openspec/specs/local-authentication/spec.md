# Local Authentication Specification

## Purpose
Gerenciamento de contas locais com e-mail e senha, autenticação segura utilizando algoritmo Argon2 e isolamento estrito de dados pessoais sem atribuição de papéis ou permissões.

## Requirements

### Requirement: Cadastro Local
O sistema deve permitir o cadastro de novos usuários com e-mail, nome e senha.
- O e-mail deve ser validado quanto ao formato e deve ser único no sistema.
- A senha deve ser armazenada exclusivamente na forma de hash utilizando o algoritmo Argon2.
- A conta é criada ativa por padrão.

### Requirement: Autenticação Local
O sistema deve validar credenciais fornecidas (e-mail e senha).
- Se as credenciais estiverem corretas, uma sessão válida é gerada.
- Se o e-mail não existir ou a senha estiver incorreta, o sistema deve responder com a mesma mensagem de erro genérica ("Credenciais inválidas") para mitigar ataques de enumeração e timing attacks.
- Usuários sem senha definida (contas criadas via redes sociais) devem ser instruídos a usar o login social correspondente.
