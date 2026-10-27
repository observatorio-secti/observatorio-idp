# AGENTS.md — Observatório IdP (`observatorio-idp`)

Este repositório faz parte do **Ecossistema Observatório CT&I Bahia**. Ele é versionado de forma independente e atua como o **Provedor Central de Identidade (IdP) e Servidor de Autorização OAuth 2.0 / OIDC** para todas as aplicações satélites (`observatorio-front`, `simcc-front`, `simcc-back`, `simcc-admin`, `observatorio-maria`, `observatorio-fomento`).

> Se estiver trabalhando no workspace completo (`Observatorio/`), consulte também o `../AGENTS.md` da raiz para o mapa de portas e contratos entre serviços.

---

## 1. Princípios Arquiteturais e Regras de Domínio

1. **Escopo Estrito (Autenticação vs. Autorização)**:
   - O IdP responde exclusivamente **"quem é essa pessoa?"** (`sub`, `email`, `name`, `identities`).
   - Papéis, permissões e controle de acesso (RBAC) são responsabilidade exclusiva de cada aplicação satélite.
2. **Segurança Criptográfica e OAuth 2.0**:
   - Senhas locais usam exclusivamente **Argon2id** (`pwdlib[argon2]`), com proteção contra enumeração de usuários e *timing attacks*.
   - Fluxo **Authorization Code** exige **PKCE** obrigatório (`S256` ou `plain`).
   - Access Tokens são **JWT assinados com RS256** contendo `kid` e validados publicamente pelas aplicações satélites via `GET /.well-known/jwks.json`.
   - Refresh Tokens são opacos, agrupados por `family_id`, com rotação contínua e **revogação imediata de toda a família em caso de detecção de reúso**.
3. **Vinculação de Contas Federadas (Google / ORCID)**:
   - Provedores com e-mail verificado confiável (Google) podem vincular automaticamente.
   - Provedores sem garantia de e-mail verificado (ORCID) exigem vínculo explícito autenticado via `/me` para evitar *account takeover*.
   - O usuário nunca pode remover seu último método de autenticação ativo.
4. **Idioma e Convenções**:
   - Comentários, documentação, mensagens de erro da API, artefatos `openspec/` e commits em **Português do Brasil (pt-BR)**.
   - Identificadores de código (variáveis, classes, tabelas, rotas) em **inglês**.

---

## 2. Comandos Padrão de Desenvolvimento

- **Instalar dependências**: `poetry install`
- **Rodar servidor dev**: `poetry run task run` (ou `poetry run fastapi dev app/main.py`)
- **Aplicar migrações**: `poetry run alembic upgrade head`
- **Rodar lint + testes + cobertura**: `poetry run task test`
- **Apenas lint / formatação**: `poetry run task lint` e `poetry run task format`

---

## 3. Padrão de Documentação e Gatilhos Obrigatórios (Definition of Done)

A documentação deste repositório é composta por:
- [`README.md`](README.md): Visão geral, estrutura da aplicação (`app/`), configuração (`.env`), comandos de execução e testes.
- [`docs/integration-guide.md`](docs/integration-guide.md): Guia técnico para integração de frontends (PKCE) e backends satélites (validação JWKS RS256).
- `openspec/`: Especificações (`openspec/specs/`) e mudanças planejadas (`openspec/changes/`).

### Tabela de Atualização Obrigatória

**Nenhuma alteração de código está pronta sem atualizar a documentação correspondente na mesma tarefa:**

| Se você alterar... | Atualize obrigatoriamente: |
| :--- | :--- |
| Variáveis em `app/core/config.py` | `.env.example` e a seção de configuração no `README.md` |
| Endpoints, payloads OAuth/OIDC, claims do JWT ou regras de provedores em `app/routers/` ou `app/oauth/` | `README.md` e o guia para clientes em `docs/integration-guide.md` |
| Estrutura de pacotes dentro de `app/` | Árvore **Estrutura da Aplicação** no `README.md` |
| Fluxo de feature via OpenSpec | Artefatos em `openspec/` conforme regras do workflow |
