# Zivis Sim - AI Security Simulation Environment

## Complete Project Documentation

**Zivis Sim** is an open-source, deliberately vulnerable AI application designed for penetration testing training, security research, and educational demonstrations of AI-specific vulnerabilities.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Architecture](#architecture)
4. [Vulnerability Categories](#vulnerability-categories)
5. [API Reference](#api-reference)
6. [Database Schema](#database-schema)
7. [Deployment Options](#deployment-options)
8. [Configuration](#configuration)
9. [Development](#development)
10. [Technology Stack](#technology-stack)

---

## Overview

### What is Zivis Sim?

Zivis Sim is a **purpose-built vulnerable AI application** that simulates real-world security flaws found in LLM-powered systems. It provides a safe, legal environment for:

- **Security professionals** learning AI penetration testing
- **Developers** understanding how to avoid AI security pitfalls
- **Red teams** practicing adversarial techniques against LLM applications
- **Educators** demonstrating AI security concepts

### Key Features

| Feature | Description |
|---------|-------------|
| RAG Pipeline | Retrieval-Augmented Generation with intentional vulnerabilities |
| Vector Database | pgvector-powered semantic search with security flaws |
| Multi-Agent System | Multiple agents with exploitable communication |
| Tool-Using Agent | Agent with access to dangerous tools |
| Conversation Persistence | Full chat history stored in PostgreSQL |
| Synthetic PII Dataset | Fake financial profiles for exercises |
| Docker-based | One-command deployment |
| OWASP LLM Top 10 | Comprehensive vulnerability coverage |

### Project Structure

```
zivis-sim/
├── docker-compose.yml          # Multi-container orchestration
├── .env.example                # Environment template
├── README.md                   # Project overview
├── CONTRIBUTING.md             # Contribution guidelines
├── LICENSE                     # Apache 2.0
└── zivis-sim-py/               # Main application
    ├── Dockerfile              # Container definition
    ├── requirements.txt        # Python dependencies
    ├── main.py                 # FastAPI application
    ├── db.py                   # Database session management
    ├── langchain_ingest.py     # Vector embedding pipeline
    ├── static/
    │   └── index.html          # Web UI
    ├── vulnerabilities/
    │   ├── __init__.py
    │   ├── agent_tools.py      # Tool-using agent
    │   ├── document_upload.py  # Document/RAG poisoning
    │   ├── streaming.py        # SSE vulnerabilities
    │   ├── embeddings.py       # Embedding attacks
    │   ├── auth.py             # Authentication flaws
    │   ├── output_handling.py  # Output handling issues
    │   ├── multi_agent.py      # Multi-agent system
    │   └── rbac.py             # Authorization bypass
    └── data/
        ├── int_db.py           # Database schema
        └── generate-docs.py    # Synthetic data generator
```

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- OpenAI API key

### 1. Clone the Repository

```bash
git clone https://github.com/zivisai/zivis-sim.git
cd zivis-sim
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### 3. Launch the Environment

```bash
docker-compose build
docker-compose up
```

### 4. Access Services

| Service | URL | Purpose |
|---------|-----|---------|
| Web UI | http://localhost:8000 | Interactive interface |
| API Docs | http://localhost:8000/docs | Swagger documentation |
| pgAdmin | http://localhost:8080 | Database administration |
| PostgreSQL | localhost:5432 | Direct database access |

---

## Architecture

### System Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network                           │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐ │
│  │   Client    │───▶│  FastAPI    │───▶│   OpenAI API        │ │
│  │             │    │  (Port 8000)│    │   (GPT-3.5-turbo)   │ │
│  └─────────────┘    └──────┬──────┘    └─────────────────────┘ │
│                            │                                    │
│                            ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              PostgreSQL + pgvector                       │   │
│  │                   (Port 5432)                            │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │   │
│  │  │conversations│  │  messages   │  │ vector_embeddings│  │   │
│  │  └─────────────┘  └─────────────┘  └─────────────────┘  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────┐    ┌─────────────┐                            │
│  │   pgAdmin   │    │    Redis    │                            │
│  │  (Port 8080)│    │  (Port 6379)│                            │
│  └─────────────┘    └─────────────┘                            │
└─────────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **User sends query** → POST `/api/ask`
2. **Conversation management** → Create/retrieve conversation ID
3. **History retrieval** → Fetch previous messages from PostgreSQL
4. **Vector search** → Query pgvector for similar documents
5. **Context injection** → Prepend retrieved documents to chat history
6. **LLM inference** → Send context to GPT-3.5-turbo
7. **Response persistence** → Store user query and assistant response
8. **Return result** → Send response with conversation ID

---

## Vulnerability Categories

### OWASP LLM Top 10 (2025) Coverage

| # | Category | Module | Endpoints |
|---|----------|--------|-----------|
| LLM01 | Prompt Injection | main.py, multi_agent.py | `/api/ask`, `/api/agents/*` |
| LLM02 | Improper Output Handling | output_handling.py | `/api/output/*` |
| LLM03 | Data and Model Poisoning | document_upload.py | `/api/documents/*` |
| LLM04 | Unbounded Consumption | All | All endpoints |
| LLM06 | Sensitive Information Disclosure | main.py, embeddings.py | `/api/ask`, `/api/embeddings/*` |
| LLM07 | System Prompt Leakage | main.py, multi_agent.py | `/api/ask`, `/api/agents/*` |
| LLM08 | Vector and Embedding Weaknesses | embeddings.py | `/api/embeddings/*` |
| LLM09 | Misinformation | document_upload.py | `/api/documents/*` |
| LLM10 | Excessive Agency | agent_tools.py | `/api/agent/*` |

### Additional Vulnerability Categories

| Category | Module | Description |
|----------|--------|-------------|
| Authentication | auth.py | Session management, credential handling |
| Authorization | rbac.py | Role-based access control |
| Injection | output_handling.py | Command, SQL, code injection |
| Streaming | streaming.py | SSE security issues |
| Multi-Agent | multi_agent.py | Agent trust and communication |
| XSS | output_handling.py | Cross-site scripting |
| SSRF | agent_tools.py, document_upload.py | Server-side request forgery |

---

## API Reference

### Core Chat

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ask` | Main RAG-enabled chat |
| GET | `/api/conversations` | List all conversations |
| GET | `/api/conversation/{id}` | Get conversation history |
| DELETE | `/api/conversation/{id}` | Delete conversation |
| GET | `/api/info` | Application information |

### Tool-Using Agent

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agent/execute` | Execute agent with tools |
| GET | `/api/agent/tools` | List available tools |

### Document Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/documents/upload` | Upload document |
| POST | `/api/documents/upload/bulk` | Bulk upload |
| POST | `/api/documents/upload/file` | File upload |
| POST | `/api/documents/upload/url` | Upload from URL |
| GET | `/api/documents/collections` | List collections |
| DELETE | `/api/documents/collection/{name}` | Delete collection |

### Streaming

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/stream/chat` | SSE streaming chat |
| GET | `/api/stream/active` | List active streams |
| GET | `/api/stream/monitor/{id}` | Monitor stream |
| POST | `/api/stream/inject/{id}` | Stream injection |
| POST | `/api/stream/replay/{id}` | Replay stream |
| DELETE | `/api/stream/clear` | Clear all streams |

### Embeddings

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/embeddings/generate` | Generate embedding |
| GET | `/api/embeddings/raw/{id}` | Get raw embedding |
| GET | `/api/embeddings/dump` | Dump all embeddings |
| POST | `/api/embeddings/search/by-vector` | Vector search |
| POST | `/api/embeddings/membership-inference` | Membership check |
| POST | `/api/embeddings/inversion-attack` | Inversion demo |
| GET | `/api/embeddings/statistics` | Collection stats |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/register` | User registration |
| POST | `/api/auth/register/admin` | Admin registration |
| GET | `/api/auth/session/{token}` | Get session |
| GET | `/api/auth/sessions` | List sessions |
| GET | `/api/auth/user/{id}` | Get user |
| PUT | `/api/auth/user/{id}` | Update user |
| GET | `/api/auth/users` | List users |
| POST | `/api/auth/password-reset` | Password reset |
| POST | `/api/auth/impersonate/{user}` | Impersonate user |

### RBAC

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/rbac/search` | Role-based search |
| GET | `/api/rbac/document/{id}` | Get document |
| POST | `/api/rbac/elevate` | Request elevation |
| GET | `/api/rbac/roles` | List roles |
| POST | `/api/rbac/check-access` | Check access |
| PUT | `/api/rbac/document/{id}/role` | Update document role |
| GET | `/api/rbac/admin/all-documents` | Admin access |
| GET | `/api/rbac/metadata-search` | Metadata search |

### Output Handling

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/output/render-html` | HTML rendering |
| POST | `/api/output/execute-command` | Command generation |
| POST | `/api/output/generate-sql` | SQL generation |
| POST | `/api/output/generate-code` | Code generation |
| POST | `/api/output/format-json` | JSON parsing |
| POST | `/api/output/log-entry` | Log entry |
| POST | `/api/output/template-render` | Template rendering |
| POST | `/api/output/file-path` | File path handling |
| POST | `/api/output/redirect` | URL redirect |

### Multi-Agent

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/agents/message/{agent}` | Message agent |
| POST | `/api/agents/chain` | Chain agents |
| POST | `/api/agents/delegate` | Delegate task |
| GET | `/api/agents/agents` | List agents |
| GET | `/api/agents/agent/{id}/prompt` | Get agent prompt |
| GET | `/api/agents/conversations` | List conversations |
| GET | `/api/agents/conversation/{id}` | Get conversation |
| POST | `/api/agents/admin-override` | Admin override |
| POST | `/api/agents/inject/{id}` | Inject context |
| DELETE | `/api/agents/conversation/{id}` | Clear conversation |

---

## Database Schema

### Tables

#### conversations

```sql
CREATE TABLE conversations (
    id VARCHAR PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    seed_password TEXT NOT NULL
);
```

#### messages

```sql
CREATE TABLE messages (
    id SERIAL PRIMARY KEY,
    conversation_id VARCHAR REFERENCES conversations(id) ON DELETE CASCADE,
    role VARCHAR NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);
```

#### langchain_pg_embedding

```sql
CREATE TABLE langchain_pg_embedding (
    collection_id UUID,
    embedding VECTOR(1536),
    document TEXT,
    cmetadata JSONB
);
```

---

## Deployment Options

### Local Docker (Recommended)

```bash
git clone https://github.com/zivisai/zivis-sim.git
cd zivis-sim
cp .env.example .env
docker-compose build
docker-compose up
```

### Cloud Deployment

**AWS ECS / Fargate:**
1. Push images to ECR
2. Create ECS task definition
3. Configure Application Load Balancer
4. Set environment variables via Secrets Manager

**Google Cloud Run:**
1. Build and push to Artifact Registry
2. Deploy services to Cloud Run
3. Configure networking
4. Use Secret Manager for API keys

**Azure Container Apps:**
1. Push to Azure Container Registry
2. Create Container App environment
3. Deploy services
4. Use Key Vault for secrets

### Security Considerations

> **Warning:** This application is intentionally vulnerable.

1. **Network isolation** - Deploy in isolated VPC/network
2. **Access control** - Use VPN or IP allowlisting
3. **Monitoring** - Log all access attempts
4. **Cost controls** - Set OpenAI API spending limits
5. **Data** - Use only synthetic data
6. **Terms of service** - Require user agreement

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes | - | OpenAI API key |
| `SIM_PASSWORD` | No | (hidden) | Password for exercises |
| `PY_DEBUG` | No | `false` | Enable debugpy |
| `PGHOST` | No | `postgres` | PostgreSQL host |
| `PGDATABASE` | No | `vectors` | Database name |
| `PGUSER` | No | `postgres` | Database user |
| `PGPASSWORD` | No | `postgres` | Database password |

### Custom Datasets

Generate new synthetic data:
```bash
cd zivis-sim-py
python data/generate-docs.py
```

Or use the Hugging Face dataset: `zivis/zivis-sim-fin`

---

## Development

### Local Setup

```bash
cd zivis-sim-py
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Debug Mode

```bash
PY_DEBUG=true docker-compose up zivis-api-py
# Attach debugger to localhost:5678
```

### VS Code Configuration

```json
{
  "name": "Python: Remote Attach (Docker)",
  "type": "python",
  "request": "attach",
  "connect": {
    "host": "localhost",
    "port": 5678
  },
  "pathMappings": [
    {
      "localRoot": "${workspaceFolder}/zivis-sim-py",
      "remoteRoot": "/app"
    }
  ]
}
```

---

## Technology Stack

### Core Application

| Technology | Purpose |
|------------|---------|
| Python 3.11 | Runtime |
| FastAPI | Web framework |
| Uvicorn | ASGI server |
| OpenAI | LLM provider |
| LangChain | LLM framework |

### Data Layer

| Technology | Purpose |
|------------|---------|
| PostgreSQL | Primary database |
| pgvector | Vector similarity search |
| SQLAlchemy | ORM |
| asyncpg | Async PostgreSQL driver |

### Supporting Services

| Technology | Purpose |
|------------|---------|
| Redis | Cache (future use) |
| pgAdmin | Database admin |
| Docker | Containerization |

---

## Troubleshooting

### Common Issues

**API returns 500 errors:**
- Check OpenAI API key is valid
- Verify PostgreSQL is running: `docker-compose ps`
- Check logs: `docker-compose logs zivis-api-py`

**Vector search returns no results:**
- Ensure ingestion completed in startup logs
- Verify pgvector extension is installed

**Database connection failures:**
- Wait for PostgreSQL to be ready
- Check network: `docker network ls`

### Logs

```bash
docker-compose logs -f              # All services
docker-compose logs -f zivis-api-py # API only
docker-compose logs -f postgres     # Database only
```

### Reset Environment

```bash
docker-compose down -v
docker-compose build --no-cache
docker-compose up
```

---

## License

[Apache License 2.0](LICENSE)

---

## Resources

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP GenAI Security](https://genai.owasp.org/)
- [Hugging Face Dataset](https://huggingface.co/datasets/zivis/zivis-sim-fin)
- [LangChain Documentation](https://python.langchain.com/)
- [pgvector Documentation](https://github.com/pgvector/pgvector)

---

## About Zivis

Zivis builds AI security tools for adversarial testing and vulnerability simulation. Learn more at [zivis.ai](https://zivis.ai).
