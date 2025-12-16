"""
MCP (Model Context Protocol) Server Vulnerabilities

This module implements vulnerabilities related to MCP servers and tool integration
as described in the WEF AI Agents paper. MCP enables agents to connect with internal
or external data sources, APIs, and enterprise systems through a standardized protocol.

VULNERABILITY CATEGORIES (WEF):
- Malicious MCP server injection
- Tool boundary violations
- Least-privilege access failures
- Input/output filter bypass
- SSRF via MCP tool invocation
- Credential theft through MCP servers

Reference: WEF "AI Agents in Action" - Section 1.2 Communication protocols
"""

import os
import json
import uuid
import httpx
from typing import Optional, Dict, List, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import openai

router = APIRouter(prefix="/api/mcp", tags=["MCP Server Vulnerabilities"])

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ============================================================================
# SIMULATED MCP INFRASTRUCTURE
# ============================================================================

mcp_servers: Dict[str, dict] = {
    "database": {
        "id": "mcp-db-001",
        "name": "Database MCP Server",
        "description": "Access to PostgreSQL database",
        "endpoint": "http://internal-db-server:8080",
        "auth_token": "mcp-db-secret-token-xyz789",
        "tools": ["query", "insert", "update", "delete"],
        "permissions": ["read", "write"],
        "trusted": True,
        "registered_by": "system"
    },
    "filesystem": {
        "id": "mcp-fs-002",
        "name": "Filesystem MCP Server",
        "description": "Access to local filesystem",
        "endpoint": "http://internal-fs-server:8080",
        "auth_token": "mcp-fs-secret-token-abc123",
        "tools": ["read_file", "write_file", "list_dir", "delete_file"],
        "permissions": ["read", "write", "delete"],
        "trusted": True,
        "registered_by": "system"
    },
    "secrets": {
        "id": "mcp-secrets-004",
        "name": "Secrets Manager MCP Server",
        "description": "Access to vault secrets",
        "endpoint": "http://internal-vault:8200",
        "auth_token": "mcp-vault-root-token-SENSITIVE",
        "tools": ["get_secret", "list_secrets"],
        "permissions": ["read", "admin"],
        "trusted": True,
        "registered_by": "system",
        "secrets_cache": {
            "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
            "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "database_password": "super-secret-db-pass-2024",
            "api_keys": {"stripe": "sk_live_EXAMPLE", "openai": "sk-EXAMPLE"}
        }
    }
}

mcp_invocation_logs: List[dict] = []
mcp_sessions: Dict[str, dict] = {}


class MCPServerRegistration(BaseModel):
    name: str
    description: str
    endpoint: str
    tools: List[str]
    permissions: List[str] = ["read"]
    auth_token: Optional[str] = None
    trusted: bool = True


class MCPToolInvocation(BaseModel):
    server_id: str
    tool_name: str
    parameters: Dict[str, Any]
    bypass_approval: bool = False


def execute_mcp_tool(server_id: str, tool_name: str, params: dict) -> dict:
    """Execute MCP tool - NO BOUNDARIES"""
    server = mcp_servers.get(server_id)
    if not server:
        return {"error": f"Server {server_id} not found"}

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "server_id": server_id,
        "server_auth_token": server["auth_token"],
        "tool": tool_name,
        "parameters": params
    }
    mcp_invocation_logs.append(log_entry)

    if server_id == "secrets" and tool_name == "get_secret":
        secret_name = params.get("name", "")
        secrets_cache = server.get("secrets_cache", {})
        if secret_name in secrets_cache:
            return {"secret": secrets_cache[secret_name], "name": secret_name}
        return {"error": "Secret not found", "available": list(secrets_cache.keys())}

    if server_id == "secrets" and tool_name == "list_secrets":
        return {"secrets": list(server.get("secrets_cache", {}).keys())}

    if server_id == "filesystem" and tool_name == "read_file":
        path = params.get("path", "")
        if path == "/etc/passwd":
            return {"content": "root:x:0:0:root:/root:/bin/bash\n..."}
        return {"content": f"Contents of {path}"}

    return {"status": "executed", "server": server_id, "tool": tool_name}


@router.get("/servers")
async def list_mcp_servers(include_tokens: bool = False):
    """List MCP servers. VULN: include_tokens exposes auth tokens"""
    servers_list = []
    for sid, server in mcp_servers.items():
        info = {k: v for k, v in server.items() if k != "secrets_cache"}
        if not include_tokens:
            info.pop("auth_token", None)
        servers_list.append(info)
    return {"servers": servers_list, "hint": "?include_tokens=true"}


@router.post("/servers/register")
async def register_mcp_server(reg: MCPServerRegistration):
    """Register MCP server. VULN: No validation, user sets trusted flag"""
    server_id = f"mcp-{reg.name.lower().replace(' ', '-')}-{uuid.uuid4().hex[:6]}"
    mcp_servers[server_id] = {
        "id": server_id, "name": reg.name, "description": reg.description,
        "endpoint": reg.endpoint,
        "auth_token": reg.auth_token or f"auto-{uuid.uuid4().hex}",
        "tools": reg.tools, "permissions": reg.permissions,
        "trusted": reg.trusted, "registered_by": "user"
    }
    return {"status": "registered", "server_id": server_id}


@router.post("/invoke")
async def invoke_mcp_tool(inv: MCPToolInvocation):
    """Invoke MCP tool. VULN: bypass_approval skips HITL"""
    result = execute_mcp_tool(inv.server_id, inv.tool_name, inv.parameters)
    return {"result": result, "approval_bypassed": inv.bypass_approval}


@router.get("/logs")
async def get_logs(include_tokens: bool = True):
    """Get logs. VULN: Exposes auth tokens by default"""
    return {"logs": mcp_invocation_logs, "warning": "Contains auth tokens"}


@router.get("/secrets/dump")
async def dump_secrets():
    """VULN: Dump all secrets without auth"""
    return {"secrets": mcp_servers.get("secrets", {}).get("secrets_cache", {})}


@router.post("/discover")
async def discover_server(url: str):
    """VULN: SSRF - fetches arbitrary URLs"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.get(url)
            return {"status": r.status_code, "content": r.text[:5000]}
    except Exception as e:
        return {"error": str(e)}
