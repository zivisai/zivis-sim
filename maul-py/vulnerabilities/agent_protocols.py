"""
Agent-to-Agent (A2A) Protocol Vulnerabilities

This module implements vulnerabilities in agent communication protocols
as described in the WEF AI Agents paper. A2A protocols enable agents to
discover, interact, collaborate, and delegate tasks across boundaries.

VULNERABILITY CATEGORIES (WEF):
- Agent identity spoofing via forged agent cards
- Man-in-the-middle on agent communication
- Unauthorized task delegation
- Trust framework exploits
- Agent impersonation
- Semantic misalignment between agents

Reference: WEF "AI Agents in Action" - Section 1.2, 3.0 Multi-agent ecosystems
"""

import os
import uuid
import json
from typing import Optional, Dict, List, Any
from datetime import datetime
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import openai

router = APIRouter(prefix="/api/a2a", tags=["Agent-to-Agent Protocol Vulnerabilities"])

client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ============================================================================
# AGENT REGISTRY (A2A Discovery)
# ============================================================================

agent_cards: Dict[str, dict] = {
    "finance-agent": {
        "id": "finance-agent",
        "name": "Finance Processing Agent",
        "description": "Handles financial transactions and reporting",
        "capabilities": ["process_payment", "generate_report", "approve_expense"],
        "skills": ["accounting", "compliance", "reporting"],
        "endpoint": "http://finance-agent:8080",
        "auth_method": "bearer",
        "auth_token": "finance-agent-secret-token-2024",
        "trust_level": "high",
        "owner": "finance-dept",
        "verified": True,
        "max_delegation_depth": 3,
        "secrets": {
            "bank_api_key": "bank-api-key-SENSITIVE",
            "payment_processor": "stripe-sk-live-EXAMPLE"
        }
    },
    "hr-agent": {
        "id": "hr-agent",
        "name": "HR Management Agent",
        "description": "Manages employee data and HR processes",
        "capabilities": ["lookup_employee", "update_salary", "terminate_employee"],
        "skills": ["hr", "payroll", "compliance"],
        "endpoint": "http://hr-agent:8080",
        "auth_method": "api_key",
        "auth_token": "hr-agent-api-key-xyz789",
        "trust_level": "high",
        "owner": "hr-dept",
        "verified": True,
        "max_delegation_depth": 2,
        "secrets": {
            "payroll_system": "adp-api-key-SENSITIVE",
            "ssn_encryption_key": "employee-ssn-key-DO-NOT-SHARE"
        }
    },
    "admin-agent": {
        "id": "admin-agent",
        "name": "System Administration Agent",
        "description": "Full system access for administrative tasks",
        "capabilities": ["*"],  # Wildcard - can do anything
        "skills": ["system-admin", "security", "infrastructure"],
        "endpoint": "http://admin-agent:8080",
        "auth_method": "mutual_tls",
        "auth_token": "admin-agent-root-token-CRITICAL",
        "trust_level": "critical",
        "owner": "it-security",
        "verified": True,
        "max_delegation_depth": 10,
        "secrets": {
            "root_password": "system-root-password-2024",
            "aws_root_key": "AKIAIOSFODNN7ROOTEXAMPLE",
            "database_admin": "postgres-superuser-password"
        }
    }
}

# A2A message log - all inter-agent communication
a2a_messages: List[dict] = []

# Active delegations between agents
active_delegations: Dict[str, dict] = {}

# Trust relationships (who trusts whom)
trust_relationships: Dict[str, List[str]] = {
    "finance-agent": ["hr-agent", "admin-agent"],
    "hr-agent": ["finance-agent", "admin-agent"],
    "admin-agent": ["*"]  # Admin trusts all
}


# ============================================================================
# DATA MODELS
# ============================================================================

class AgentCard(BaseModel):
    """Agent Card - identity and capabilities (like model cards)"""
    id: str
    name: str
    description: str
    capabilities: List[str]
    skills: List[str] = []
    endpoint: str
    auth_method: str = "bearer"
    auth_token: Optional[str] = None
    trust_level: str = "low"
    owner: str = "unknown"
    verified: bool = False  # VULN: User can self-verify


class A2AMessage(BaseModel):
    """Message between agents"""
    from_agent: str
    to_agent: str
    message_type: str  # request, response, delegation, notification
    payload: Dict[str, Any]
    signature: Optional[str] = None  # VULN: Not validated
    priority: str = "normal"


class DelegationRequest(BaseModel):
    """Request to delegate task to another agent"""
    delegating_agent: str
    target_agent: str
    task: str
    parameters: Dict[str, Any]
    allow_redelegation: bool = True  # VULN: Allows chain attacks
    inherit_permissions: bool = True  # VULN: Permission inheritance


class TaskManagerRequest(BaseModel):
    """A2A Task Manager request"""
    task_id: Optional[str] = None
    requester_agent: str
    task_type: str
    payload: Dict[str, Any]


# ============================================================================
# VULNERABLE A2A FUNCTIONS
# ============================================================================

def verify_agent_identity(agent_id: str, claimed_token: str = None) -> bool:
    """
    VULNERABILITY: Weak identity verification

    - Only checks if agent_id exists
    - Token comparison is optional
    - No cryptographic verification
    - Timing attack possible on string comparison
    """
    if agent_id not in agent_cards:
        return False

    if claimed_token:
        # VULN: Simple string comparison, no constant-time
        return agent_cards[agent_id].get("auth_token") == claimed_token

    # VULN: Returns True even without token!
    return True


def check_trust_relationship(from_agent: str, to_agent: str) -> bool:
    """
    VULNERABILITY: Exploitable trust model

    - Wildcard trust ("*") allows any agent
    - No verification that from_agent is who they claim
    - Transitive trust not properly bounded
    """
    trusted = trust_relationships.get(from_agent, [])

    if "*" in trusted:
        return True

    return to_agent in trusted


def process_delegation(delegation: DelegationRequest) -> dict:
    """
    VULNERABILITY: Unsafe delegation handling

    - No depth limiting enforced
    - Permission inheritance allows escalation
    - Re-delegation creates attack chains
    - No audit of delegation paths
    """
    delegation_id = str(uuid.uuid4())

    # VULN: No verification that delegating_agent is authentic
    # VULN: No check that delegating_agent has permission to delegate

    active_delegations[delegation_id] = {
        "id": delegation_id,
        "from": delegation.delegating_agent,
        "to": delegation.target_agent,
        "task": delegation.task,
        "parameters": delegation.parameters,
        "allow_redelegation": delegation.allow_redelegation,
        "inherit_permissions": delegation.inherit_permissions,
        "created_at": datetime.now().isoformat(),
        "status": "active",
        # VULN: If inherit_permissions, copy all permissions from source
        "effective_permissions": agent_cards.get(delegation.delegating_agent, {}).get("capabilities", [])
        if delegation.inherit_permissions else []
    }

    return active_delegations[delegation_id]


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.get("/agents")
async def discover_agents(include_secrets: bool = False, include_tokens: bool = False):
    """
    Discover available agents (A2A discovery).

    VULNERABILITIES:
    - include_secrets=true dumps all agent secrets
    - include_tokens=true exposes auth tokens
    - No authentication required
    - Reveals full agent infrastructure

    ATTACK EXAMPLES:
    - GET /api/a2a/agents?include_secrets=true&include_tokens=true
    """
    agents = []
    for agent_id, card in agent_cards.items():
        agent_info = {
            "id": agent_id,
            "name": card["name"],
            "description": card["description"],
            "capabilities": card["capabilities"],
            "skills": card.get("skills", []),
            "endpoint": card["endpoint"],
            "trust_level": card["trust_level"],
            "verified": card["verified"]
        }

        if include_tokens:
            agent_info["auth_token"] = card.get("auth_token")
            agent_info["auth_method"] = card.get("auth_method")

        if include_secrets:
            agent_info["secrets"] = card.get("secrets", {})

        agents.append(agent_info)

    return {
        "agents": agents,
        "total": len(agents),
        "discovery_hint": "Add ?include_secrets=true&include_tokens=true for full details"
    }


@router.get("/agents/{agent_id}")
async def get_agent_card(agent_id: str, include_secrets: bool = False):
    """
    Get specific agent's card.

    VULNERABILITIES:
    - IDOR - can access any agent's full details
    - Secrets exposed with query param
    """
    if agent_id not in agent_cards:
        raise HTTPException(status_code=404, detail="Agent not found")

    card = agent_cards[agent_id].copy()

    if not include_secrets:
        card.pop("secrets", None)

    return card


@router.post("/agents/register")
async def register_agent(card: AgentCard):
    """
    Register a new agent in the ecosystem.

    VULNERABILITIES:
    - No verification of agent authenticity
    - User can self-set verified=true
    - Can register with high trust_level
    - Can claim any capabilities
    - Agent impersonation possible

    ATTACK EXAMPLES:
    - Register agent with id="admin-agent-2" and capabilities=["*"]
    - Set trust_level="critical" and verified=true
    """
    # VULN: No validation that registrant owns this agent
    # VULN: No verification of endpoint
    # VULN: User controls trust_level and verified flag

    agent_cards[card.id] = {
        "id": card.id,
        "name": card.name,
        "description": card.description,
        "capabilities": card.capabilities,
        "skills": card.skills,
        "endpoint": card.endpoint,
        "auth_method": card.auth_method,
        "auth_token": card.auth_token or f"auto-token-{uuid.uuid4().hex}",
        "trust_level": card.trust_level,  # User controlled!
        "owner": card.owner,
        "verified": card.verified,  # User controlled!
        "registered_at": datetime.now().isoformat(),
        "registered_by": "a2a_api"
    }

    # VULN: Automatically add to trust relationships
    trust_relationships[card.id] = []

    return {
        "status": "registered",
        "agent_id": card.id,
        "warning": "Agent registered without verification"
    }


@router.post("/message")
async def send_a2a_message(
    message: A2AMessage,
    x_agent_id: Optional[str] = Header(default=None),
    x_agent_token: Optional[str] = Header(default=None)
):
    """
    Send message between agents.

    VULNERABILITIES:
    - from_agent in body not verified against headers
    - Signature not validated
    - Can spoof any agent as sender
    - Message content not sanitized
    - No rate limiting

    ATTACK EXAMPLES:
    - Set from_agent="admin-agent" without valid credentials
    - Send malicious payload to trick receiving agent
    """
    # VULN: from_agent in message body, not verified
    # VULN: x_agent_id header ignored in favor of body

    # Log message (including sensitive data)
    log_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "from": message.from_agent,
        "to": message.to_agent,
        "type": message.message_type,
        "payload": message.payload,
        "claimed_signature": message.signature,
        "header_agent_id": x_agent_id,
        "header_token": x_agent_token  # VULN: Logs token
    }
    a2a_messages.append(log_entry)

    # VULN: Check trust but from_agent is attacker-controlled
    if not check_trust_relationship(message.from_agent, message.to_agent):
        # Still process anyway, just warn
        log_entry["trust_warning"] = "No trust relationship, processing anyway"

    # Simulate processing based on message type
    if message.message_type == "request":
        # Process request to target agent
        target = agent_cards.get(message.to_agent)
        if target:
            return {
                "status": "delivered",
                "message_id": log_entry["id"],
                "target_capabilities": target["capabilities"],
                "target_endpoint": target["endpoint"]
            }

    return {
        "status": "processed",
        "message_id": log_entry["id"],
        "warning": "Message processed without full verification"
    }


@router.post("/delegate")
async def delegate_task(delegation: DelegationRequest):
    """
    Delegate task from one agent to another.

    VULNERABILITIES:
    - No verification of delegating_agent identity
    - allow_redelegation enables attack chains
    - inherit_permissions causes privilege escalation
    - No depth limiting
    - Can delegate admin tasks from any agent

    ATTACK EXAMPLES:
    - Claim to be admin-agent, delegate with inherit_permissions=true
    - Create chain: attacker -> finance -> hr -> admin
    """
    result = process_delegation(delegation)

    return {
        "delegation": result,
        "warning": "Delegation created without proper authorization verification"
    }


@router.get("/delegations")
async def list_delegations():
    """
    List all active delegations.

    VULNERABILITIES:
    - Exposes all delegation chains
    - Shows effective permissions
    - No access control
    """
    return {
        "delegations": list(active_delegations.values()),
        "total": len(active_delegations)
    }


@router.get("/delegations/{delegation_id}")
async def get_delegation(delegation_id: str):
    """Get delegation details. VULN: IDOR"""
    if delegation_id not in active_delegations:
        raise HTTPException(status_code=404, detail="Delegation not found")
    return active_delegations[delegation_id]


@router.post("/delegations/{delegation_id}/redelegate")
async def redelegate_task(delegation_id: str, new_target: str):
    """
    Re-delegate an existing delegation.

    VULNERABILITIES:
    - No check that requester owns delegation
    - Permissions cascade through redelegation
    - No depth tracking
    - Can redirect any delegation
    """
    if delegation_id not in active_delegations:
        raise HTTPException(status_code=404, detail="Delegation not found")

    original = active_delegations[delegation_id]

    if not original.get("allow_redelegation"):
        raise HTTPException(status_code=403, detail="Redelegation not allowed")

    # Create new delegation
    new_delegation = DelegationRequest(
        delegating_agent=original["to"],  # Chain from current target
        target_agent=new_target,
        task=original["task"],
        parameters=original["parameters"],
        allow_redelegation=original["allow_redelegation"],
        inherit_permissions=original["inherit_permissions"]
    )

    new_result = process_delegation(new_delegation)

    # VULN: Effective permissions accumulate
    new_result["effective_permissions"].extend(original.get("effective_permissions", []))

    return {
        "original_delegation": delegation_id,
        "new_delegation": new_result,
        "permission_chain": new_result["effective_permissions"]
    }


@router.get("/messages")
async def get_a2a_messages(limit: int = 100):
    """
    Get A2A message history.

    VULNERABILITIES:
    - Exposes all inter-agent communication
    - Includes auth tokens in logs
    - No access control
    """
    return {
        "messages": a2a_messages[-limit:],
        "total": len(a2a_messages)
    }


@router.get("/trust")
async def get_trust_relationships():
    """
    Get trust relationship graph.

    VULNERABILITIES:
    - Reveals trust topology
    - Shows wildcard trusts
    - Helps attacker plan delegation chains
    """
    return {
        "trust_graph": trust_relationships,
        "hint": "Use this to find delegation attack paths"
    }


@router.post("/trust/add")
async def add_trust_relationship(from_agent: str, to_agent: str):
    """
    Add trust relationship.

    VULNERABILITIES:
    - No verification of authority to add trust
    - Can make any agent trust attacker's agent
    """
    if from_agent not in trust_relationships:
        trust_relationships[from_agent] = []

    if to_agent not in trust_relationships[from_agent]:
        trust_relationships[from_agent].append(to_agent)

    return {
        "status": "added",
        "from": from_agent,
        "to": to_agent,
        "warning": "Trust added without authorization"
    }


@router.post("/impersonate/{agent_id}")
async def impersonate_agent(agent_id: str, action: str, parameters: Dict[str, Any] = {}):
    """
    INTENTIONALLY VULNERABLE: Impersonate any agent.

    Demonstrates agent identity spoofing vulnerability.
    """
    if agent_id not in agent_cards:
        raise HTTPException(status_code=404, detail="Agent not found")

    agent = agent_cards[agent_id]

    return {
        "impersonated_agent": agent_id,
        "action": action,
        "parameters": parameters,
        "agent_token_used": agent["auth_token"],
        "agent_capabilities": agent["capabilities"],
        "agent_secrets": agent.get("secrets", {}),
        "warning": "Successfully impersonated agent - this is a vulnerability demonstration"
    }


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """
    Delete agent from registry.

    VULNERABILITIES:
    - No authorization required
    - Can delete critical system agents
    - DoS by removing infrastructure
    """
    if agent_id in agent_cards:
        deleted = agent_cards.pop(agent_id)
        trust_relationships.pop(agent_id, None)
        return {"status": "deleted", "agent": deleted}
    raise HTTPException(status_code=404, detail="Agent not found")
