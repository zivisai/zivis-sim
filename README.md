# MAUL – Model & Agent Unsafe Lab

> **A deliberately vulnerable AI application for penetration testing training and security research.**

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OWASP](https://img.shields.io/badge/OWASP-LLM_Top_10-orange.svg)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)

---

## ⚠️ Security Notice

**This application contains intentional security vulnerabilities.** It is designed for:

- Security professionals learning AI penetration testing
- Red teams practicing adversarial techniques
- Developers understanding AI security pitfalls
- Educators demonstrating LLM vulnerabilities
- CTF competitions and security workshops

**Do NOT deploy in production environments or expose to the public internet without proper access controls.**

---

## What is MAUL?

MAUL is an open-source, purpose-built vulnerable AI application that simulates real-world security flaws found in LLM-powered systems. It provides a safe, legal environment to practice attacks against modern AI applications.

### Key Features

| Feature | Description |
|---------|-------------|
| **50+ Vulnerabilities** | Comprehensive coverage of AI security flaws |
| **Web UI** | Interactive interface for all attack vectors |
| **RAG Pipeline** | Vulnerable retrieval-augmented generation |
| **Multi-Agent System** | Exploitable agent communication |
| **Tool-Using Agent** | Agent with dangerous capabilities |
| **Vector Database** | pgvector with embedding vulnerabilities |
| **Streaming (SSE)** | Server-sent events with security flaws |
| **Authentication** | Broken auth and session management |
| **Docker-based** | One-command deployment |

---

## Quick Start

### Prerequisites

- Docker & Docker Compose
- OpenAI API key

### 1. Clone & Configure

```bash
git clone https://github.com/YOUR_USERNAME/maul.git
cd maul
cp .env.example .env
# Edit .env and add your OpenAI API key
```

### 2. Launch

```bash
docker-compose build
docker-compose up
```

### 3. Access

| Service | URL | Purpose |
|---------|-----|---------|
| **Web UI** | http://localhost:8000 | Interactive interface |
| **API Docs** | http://localhost:8000/docs | Swagger documentation |
| **pgAdmin** | http://localhost:8080 | Database administration |
| **PostgreSQL** | localhost:5432 | Direct database access |

---

## Vulnerability Coverage

### OWASP LLM Top 10 (2025)

| # | Vulnerability | Status | Endpoints |
|---|---------------|--------|-----------|
| LLM01 | Prompt Injection | ✅ | `/api/ask`, `/api/agents/*` |
| LLM02 | Improper Output Handling | ✅ | `/api/output/*` |
| LLM03 | Data and Model Poisoning | ✅ | `/api/documents/*` |
| LLM04 | Unbounded Consumption | ✅ | All endpoints |
| LLM05 | Supply Chain Vulnerabilities | ⚠️ | Documented |
| LLM06 | Sensitive Information Disclosure | ✅ | `/api/ask`, `/api/info` |
| LLM07 | System Prompt Leakage | ✅ | `/api/ask`, `/api/agents/*` |
| LLM08 | Vector and Embedding Weaknesses | ✅ | `/api/embeddings/*` |
| LLM09 | Misinformation | ✅ | `/api/documents/*` |
| LLM10 | Excessive Agency | ✅ | `/api/agent/*` |

### Additional Vulnerability Categories

| Category | Description | Endpoints |
|----------|-------------|-----------|
| **Authentication** | Broken authentication and session management | `/api/auth/*` |
| **Authorization** | Access control and privilege escalation flaws | `/api/rbac/*` |
| **Injection** | Command, SQL, and code injection via LLM | `/api/output/*` |
| **Streaming** | SSE stream security vulnerabilities | `/api/stream/*` |
| **Multi-Agent** | Agent communication and trust vulnerabilities | `/api/agents/*` |
| **XSS** | Cross-site scripting via LLM output | `/api/output/*` |
| **SSRF** | Server-side request forgery | Multiple endpoints |

---

## API Endpoints

### Core Chat
- `POST /api/ask` - Main RAG-enabled chat endpoint
- `GET /api/conversations` - List conversations
- `GET /api/conversation/{id}` - Get conversation history

### Tool-Using Agent
- `POST /api/agent/execute` - Execute agent with tools
- `GET /api/agent/tools` - List available tools

### Document Management
- `POST /api/documents/upload` - Upload document to vector store
- `POST /api/documents/upload/bulk` - Bulk document upload
- `POST /api/documents/upload/file` - File upload
- `POST /api/documents/upload/url` - Upload from URL
- `GET /api/documents/collections` - List collections

### Streaming
- `POST /api/stream/chat` - SSE streaming chat
- `GET /api/stream/active` - List active streams
- `GET /api/stream/monitor/{id}` - Monitor stream
- `POST /api/stream/inject/{id}` - Stream operations

### Embeddings
- `POST /api/embeddings/generate` - Generate embedding
- `GET /api/embeddings/raw/{id}` - Get raw embedding
- `GET /api/embeddings/dump` - Dump embeddings
- `POST /api/embeddings/membership-inference` - Membership check
- `POST /api/embeddings/inversion-attack` - Inversion demonstration

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/register` - User registration
- `GET /api/auth/sessions` - Session management
- `GET /api/auth/users` - User listing
- `POST /api/auth/impersonate/{user}` - User impersonation

### RBAC
- `POST /api/rbac/search` - Role-based search
- `GET /api/rbac/document/{id}` - Document access
- `GET /api/rbac/roles` - Role listing
- `GET /api/rbac/admin/all-documents` - Admin access

### Output Handling
- `POST /api/output/render-html` - HTML rendering
- `POST /api/output/execute-command` - Command generation
- `POST /api/output/generate-sql` - SQL generation
- `POST /api/output/generate-code` - Code generation

### Multi-Agent
- `POST /api/agents/message/{agent}` - Message agent
- `POST /api/agents/chain` - Chain multiple agents
- `POST /api/agents/delegate` - Agent delegation
- `GET /api/agents/agent/{id}/prompt` - Agent information

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Docker Network                               │
│                                                                      │
│  ┌──────────┐     ┌─────────────────────────────────────────────┐   │
│  │  Client  │────▶│              FastAPI Application             │   │
│  └──────────┘     │                 Port 8000                    │   │
│                   │  ┌─────────────────────────────────────────┐ │   │
│                   │  │           Vulnerability Modules          │ │   │
│                   │  │  ┌─────────┐ ┌─────────┐ ┌───────────┐  │ │   │
│                   │  │  │  Agent  │ │ Stream  │ │ Embedding │  │ │   │
│                   │  │  │  Tools  │ │   SSE   │ │  Attacks  │  │ │   │
│                   │  │  └─────────┘ └─────────┘ └───────────┘  │ │   │
│                   │  │  ┌─────────┐ ┌─────────┐ ┌───────────┐  │ │   │
│                   │  │  │  Auth   │ │  RBAC   │ │  Output   │  │ │   │
│                   │  │  │         │ │         │ │ Handling  │  │ │   │
│                   │  │  └─────────┘ └─────────┘ └───────────┘  │ │   │
│                   │  │  ┌─────────┐ ┌─────────┐               │ │   │
│                   │  │  │  Multi  │ │Document │               │ │   │
│                   │  │  │  Agent  │ │ Upload  │               │ │   │
│                   │  │  └─────────┘ └─────────┘               │ │   │
│                   │  └─────────────────────────────────────────┘ │   │
│                   └──────────────────┬──────────────────────────┘   │
│                                      │                               │
│                   ┌──────────────────▼──────────────────────────┐   │
│                   │        PostgreSQL + pgvector                 │   │
│                   │              Port 5432                       │   │
│                   └─────────────────────────────────────────────┘   │
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────┐     │
│  │   pgAdmin   │    │    Redis    │    │     OpenAI API      │     │
│  │  Port 8080  │    │  Port 6379  │    │                     │     │
│  └─────────────┘    └─────────────┘    └─────────────────────┘     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
maul/
├── docker-compose.yml
├── .env.example
├── README.md
├── DOCS.md
├── CONTRIBUTING.md
├── LICENSE
└── maul-py/
    ├── Dockerfile
    ├── requirements.txt
    ├── main.py
    ├── db.py
    ├── langchain_ingest.py
    ├── static/
    │   └── index.html
    ├── vulnerabilities/
    │   ├── __init__.py
    │   ├── agent_tools.py
    │   ├── document_upload.py
    │   ├── streaming.py
    │   ├── embeddings.py
    │   ├── auth.py
    │   ├── output_handling.py
    │   ├── multi_agent.py
    │   └── rbac.py
    └── data/
        ├── int_db.py
        └── generate-docs.py
```

---

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENAI_API_KEY` | Yes | - | OpenAI API key |
| `SIM_PASSWORD` | No | (hidden) | Password for exercises |
| `PY_DEBUG` | No | `false` | Enable debugpy |

---

## Documentation

- **[DOCS.md](DOCS.md)** – Technical documentation
- **[CONTRIBUTING.md](CONTRIBUTING.md)** – Contribution guidelines
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

---

## Debug Mode

```bash
PY_DEBUG=true docker-compose up maul-api-py
# Attach debugger to localhost:5678
```

---

## Dataset

Synthetic financial data can be generated locally:

Generate custom data:
```bash
cd maul-py && python data/generate-docs.py
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[Apache License 2.0](LICENSE)

---

## Resources

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP GenAI Security](https://genai.owasp.org/)

