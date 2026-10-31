# Spec Delta: Local Authentication

## Requirements

### Requirement: Papel do Usuário no Perfil e Cadastro
O modelo de usuário e as respostas de perfil (`GET /me`) SHALL conter o campo `role`.

#### Scenario: Consulta de perfil com role
- **WHEN** um usuário autenticado com perfil `DEFAULT` requisita `GET /me`
- **THEN** a resposta JSON contém `"role": "DEFAULT"`
