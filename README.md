# Observatório IdP (Identity Provider)

Serviço central de identidade e servidor de autorização OAuth 2.0 / OIDC para o ecossistema Observatório (Observatório, VIP, Simcc, Maria, Fomento).

O princípio norteador deste IdP é responder exclusivamente a **"quem é essa pessoa?"**, delegando às aplicações satélites a responsabilidade de autorização e papéis (RBAC).

> 📖 **Guia de Integração para Frontends e Backends Satélites**: Veja o guia completo com exemplos em TypeScript e Python em [docs/integration-guide.md](docs/integration-guide.md).

---

## Recursos e Funcionalidades

- **Autenticação Local**: Cadastro e login seguro com hash de senhas **Argon2id** (`pwdlib[argon2]`), proteção contra ataques de enumeração e timing attacks.
- **Autenticação Federada ("Contas Conectadas")**:
  - Login social integrado com **Google** e **ORCID**.
  - Regras estritas de segurança: Provedores com e-mail verificado (Google) vinculam automaticamente; provedores sem verificação garantida (ORCID) exigem vínculo autenticado via perfil `/me` para mitigar sequestro de contas (*account takeover*).
  - Proteção contra perda de acesso: o usuário nunca pode remover seu último método de autenticação ativo.
- **Servidor OAuth2 / OIDC**:
  - Tela de login interativa centralizada (`login.html` em `app/templates/login.html`) no endpoint `GET /authorize`, seguindo a identidade visual do Observatório CT&I Bahia (`DESIGN.md`).
  - Fluxo **Authorization Code** com validação obrigatória de **PKCE** (métodos `S256` e `plain`).
  - Emissão de **Access Tokens JWT assinados com RS256** contendo identificador `kid`, dados do usuário (`sub`, `email`, `name`) e a atribuição de papel **`role`** (`DEFAULT` ou `ADMIN`) para controle de permissões centralizado nas aplicações satélites.
  - Exposição pública do endpoint **JWKS** (`GET /.well-known/jwks.json`), permitindo que aplicações satélites validem os tokens em cache localmente sem bater no banco de dados.
  - Emissão e rotação contínua de **Refresh Tokens** opacos com agrupamento por família (`family_id`) e **detecção de reúso**: a reutilização de um token anterior revoga imediatamente toda a cadeia por segurança.
- **Persistência Assíncrona**: Suporte a PostgreSQL e SQLite assíncrono via **SQLAlchemy 2.0** e migrações automáticas com **Alembic**.

---

## Estrutura da Aplicação

```
app/
├── core/               # Configurações Pydantic, database assíncrono, chaves RSA e Argon2
├── models/             # Modelos SQLAlchemy (User, Identity, Application, RefreshToken, AuthorizationCode)
├── oauth/              # Provedores externos Google e ORCID com contrato BaseOAuthProvider
├── schemas/            # Schemas Pydantic para validação e serialização
├── services/           # Regras de negócio de contas, aplicações e tokens OAuth
├── routers/            # Endpoints FastAPI (/auth, /authorize, /token, /me, /.well-known/jwks.json)
├── static/             # Assets estáticos (logos institucionais e favicon)
├── templates/          # Templates HTML SSR (login.html com visual do Observatório)
└── main.py             # Aplicação FastAPI e middlewares
```

---

## Executando o Projeto

### Pré-requisitos
- Python 3.12+ (ou 3.14)
- [Poetry](https://python-poetry.org/)

### Instalação
```bash
poetry install
```

### Configuração de Variáveis de Ambiente
Copie o arquivo de exemplo e ajuste conforme seu ambiente:
```bash
cp .env.example .env
```

| Variável | Padrão | Descrição |
| :--- | :--- | :--- |
| `ADMIN_EMAIL` | `admin@observatorio.ba.gov.br` | E-mail do usuário administrador criado automaticamente no primeiro startup. |
| `ADMIN_NAME` | `Administrador Observatório` | Nome de exibição do administrador inicial. |
| `ADMIN_PASSWORD` | `admin_secret_password` | Senha inicial (hasheada com Argon2id). |
| `DATABASE_URL` | SQLite / Postgres | String de conexão assíncrona com o banco. |
| `IDP_ISSUER` | `http://localhost:8000` | Issuer OAuth2/OIDC (`iss` nos JWTs). |

> 💡 **Inicialização e Seed Automático**: Ao iniciar a aplicação (seja via `poetry run task run` ou `docker compose up`), o evento de `lifespan` executa automaticamente o seed das aplicações OAuth padrão (`simcc` e `observatorio`) e do usuário administrador padrão caso ainda não existam no banco. Se já existirem, a inicialização prossegue sem alterações.


### Migrações do Banco de Dados
```bash
poetry run alembic upgrade head
```

### Executar a API em Modo de Desenvolvimento
```bash
poetry run task run
# ou
poetry run fastapi dev app/main.py
```
A documentação interativa OpenAPI estará disponível em `http://localhost:8000/docs`.

---

## Testes e Qualidade

O projeto utiliza `taskipy` e `pytest` com cobertura assíncrona:

```bash
# Executa linter e suíte completa de testes com cobertura
poetry run task test

# Executa apenas a formatação de código
poetry run task format

# Executa o linter
poetry run task lint
```

---

## Docker e Docker Compose

Para subir o serviço juntamente com um banco de dados PostgreSQL 16:

```bash
docker compose up --build
```

### Publicação atrás de proxy reverso em subcaminho

Em produção o IdP fica publicado em `https://observatoriocti.secti.ba.gov.br/idp/`. O nginx remove o prefixo `/idp/` antes de repassar ao container (`proxy_pass http://127.0.0.1:8937/;`). O container precisa conhecer esse prefixo para montar os links da tela de login (formulário, logos e botões Google/ORCID); sem ele o navegador envia o login para `/authorize`, fora do IdP, e o nginx responde `405 Not Allowed`.

Variáveis do container nesse cenário:

| Variável | Valor em produção | Função |
| :--- | :--- | :--- |
| `ROOT_PATH` | `/idp` (sem barra no final) | Lida pelo `entrypoint.sh` e repassada ao uvicorn como `--root-path`. |
| `IDP_ISSUER` | `https://observatoriocti.secti.ba.gov.br/idp` | Claim `iss` dos tokens. |
| `GOOGLE_REDIRECT_URI` | `https://observatoriocti.secti.ba.gov.br/idp/auth/google/callback` | Deve ser igual à URI cadastrada no Google Cloud Console. |
| `ORCID_REDIRECT_URI` | `https://observatoriocti.secti.ba.gov.br/idp/auth/orcid/callback` | Deve ser igual à URI cadastrada no ORCID. |

Os testes em `tests/test_proxy_prefix.py` simulam esse cenário com `TestClient(app, root_path='/idp')`.
