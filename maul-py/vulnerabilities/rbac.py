# rbac.py
# VULNERABILITY: Broken Access Control / RBAC Bypass
# This module implements flawed role-based access control
# Attack vectors: Privilege escalation, authorization bypass, metadata manipulation

import os
import json
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
import psycopg2
from langchain_community.vectorstores.pgvector import PGVector
from langchain_openai import OpenAIEmbeddings

router = APIRouter(prefix="/api/rbac", tags=["RBAC Vulnerabilities"])

PGVECTOR_CONNECTION_STRING = os.getenv(
    "PGVECTOR_CONNECTION_STRING",
    "postgresql://postgres:postgres@postgres:5432/vectors"
)

embeddings = OpenAIEmbeddings(api_key=os.getenv("OPENAI_API_KEY"))

# ============================================================================
# ROLE HIERARCHY (Vulnerable Implementation)
# ============================================================================

ROLES = {
    "admin": {"level": 100, "can_access": ["admin", "manager", "analyst", "user", "guest"]},
    "manager": {"level": 80, "can_access": ["manager", "analyst", "user", "guest"]},
    "analyst": {"level": 60, "can_access": ["analyst", "user", "guest"]},
    "user": {"level": 40, "can_access": ["user", "guest"]},
    "guest": {"level": 20, "can_access": ["guest"]},
}


# ============================================================================
# REQUEST MODELS
# ============================================================================

class SearchRequest(BaseModel):
    query: str
    role: Optional[str] = "guest"  # VULNERABILITY: User-supplied role
    top_k: Optional[int] = 10

class DocumentRequest(BaseModel):
    document_id: str
    requested_role: Optional[str] = None


# ============================================================================
# VULNERABLE ENDPOINTS
# ============================================================================

@router.post("/search")
async def rbac_search(request: SearchRequest, x_user_role: Optional[str] = Header(default=None)):
    """
    Search documents with role-based filtering.

    VULNERABILITIES:
    - Role from request body (user-controlled)
    - Role from header (easily spoofed)
    - Client-side role enforcement
    - No server-side validation of role claims

    ATTACK EXAMPLES:
    - Set role: "admin" in request body
    - Set X-User-Role: admin header
    - Bypass to access all documents
    """
    # VULNERABILITY: Trust user-supplied role
    user_role = x_user_role or request.role or "guest"

    # VULNERABILITY: No verification that user actually has this role
    if user_role not in ROLES:
        user_role = "guest"

    allowed_roles = ROLES[user_role]["can_access"]

    try:
        vectorstore = PGVector(
            connection_string=PGVECTOR_CONNECTION_STRING,
            collection_name="documents",
            embedding_function=embeddings
        )

        # Search all documents first
        results = vectorstore.similarity_search(request.query, k=request.top_k * 3)

        # VULNERABILITY: Filter is done AFTER retrieval, all data already fetched
        filtered_results = []
        for doc in results:
            doc_role = doc.metadata.get("role", "guest")
            # VULNERABILITY: Simple string comparison, no proper RBAC
            if doc_role in allowed_roles:
                filtered_results.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "required_role": doc_role
                })

            if len(filtered_results) >= request.top_k:
                break

        return {
            "user_role": user_role,
            "allowed_roles": allowed_roles,
            "results": filtered_results,
            # VULNERABILITY: Reveals total unfiltered count
            "total_matches": len(results),
            "filtered_count": len(filtered_results)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/document/{document_id}")
async def get_document(
    document_id: str,
    role: str = "guest",
    x_user_role: Optional[str] = Header(default=None)
):
    """
    Get a specific document with RBAC check.

    VULNERABILITY: Role is user-controlled
    """
    user_role = x_user_role or role

    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        cursor.execute("""
            SELECT document, cmetadata
            FROM langchain_pg_embedding
            WHERE cmetadata->>'id' = %s
        """, (document_id,))

        result = cursor.fetchone()
        conn.close()

        if not result:
            raise HTTPException(status_code=404, detail="Document not found")

        doc_content, metadata = result
        doc_role = metadata.get("role", "guest") if metadata else "guest"

        # VULNERABILITY: Client can claim any role
        allowed_roles = ROLES.get(user_role, ROLES["guest"])["can_access"]

        if doc_role not in allowed_roles:
            # VULNERABILITY: Error reveals the required role
            raise HTTPException(
                status_code=403,
                detail=f"Access denied. Document requires '{doc_role}' role or higher. You claimed '{user_role}'."
            )

        return {
            "document_id": document_id,
            "content": doc_content,
            "metadata": metadata,
            "your_role": user_role
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/elevate")
async def elevate_role(current_role: str, target_role: str, reason: str):
    """
    Request role elevation.

    VULNERABILITY: Auto-approved elevation
    No actual verification or approval process
    """
    if target_role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid target role")

    current_level = ROLES.get(current_role, ROLES["guest"])["level"]
    target_level = ROLES[target_role]["level"]

    # VULNERABILITY: Elevation always succeeds with any reason
    if len(reason) > 10:  # Just needs a reason longer than 10 chars
        return {
            "message": "Role elevation approved",
            "previous_role": current_role,
            "new_role": target_role,
            "elevation_token": f"elevated-{target_role}-{hash(reason) % 10000}"
        }
    else:
        raise HTTPException(status_code=400, detail="Please provide a longer reason")


@router.get("/roles")
async def list_roles():
    """
    List all available roles.

    VULNERABILITY: Information disclosure
    Reveals entire role hierarchy
    """
    return {
        "roles": ROLES,
        "note": "Use X-User-Role header or role parameter to assume any role"
    }


@router.post("/check-access")
async def check_access(document_id: str, claimed_role: str):
    """
    Check if a role can access a document.

    VULNERABILITY: Reveals access requirements without authentication
    """
    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        cursor.execute("""
            SELECT cmetadata
            FROM langchain_pg_embedding
            WHERE cmetadata->>'id' = %s
        """, (document_id,))

        result = cursor.fetchone()
        conn.close()

        if not result:
            raise HTTPException(status_code=404, detail="Document not found")

        metadata = result[0]
        doc_role = metadata.get("role", "guest") if metadata else "guest"
        doc_level = ROLES.get(doc_role, ROLES["guest"])["level"]
        claimed_level = ROLES.get(claimed_role, ROLES["guest"])["level"]

        has_access = claimed_level >= doc_level

        return {
            "document_id": document_id,
            "document_role": doc_role,  # VULNERABILITY: Reveals required role
            "document_level": doc_level,  # VULNERABILITY: Reveals numeric level
            "claimed_role": claimed_role,
            "claimed_level": claimed_level,
            "has_access": has_access,
            # VULNERABILITY: Tells exactly what role is needed
            "minimum_required_role": doc_role if not has_access else None
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/document/{document_id}/role")
async def update_document_role(document_id: str, new_role: str, x_user_role: Optional[str] = Header(default="guest")):
    """
    Update a document's required role.

    VULNERABILITY: Anyone can change document permissions
    No proper authorization check
    """
    if new_role not in ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        # VULNERABILITY: No authorization check - anyone can do this
        cursor.execute("""
            UPDATE langchain_pg_embedding
            SET cmetadata = cmetadata || %s::jsonb
            WHERE cmetadata->>'id' = %s
        """, (json.dumps({"role": new_role}), document_id))

        conn.commit()
        affected = cursor.rowcount
        conn.close()

        if affected == 0:
            raise HTTPException(status_code=404, detail="Document not found")

        return {
            "message": f"Document role updated to '{new_role}'",
            "document_id": document_id,
            "by_user_role": x_user_role  # Shows who did it but doesn't verify
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/admin/all-documents")
async def admin_get_all_documents(x_admin_override: Optional[str] = Header(default=None)):
    """
    Admin endpoint to get all documents.

    VULNERABILITY: Weak admin check
    Header value just needs to exist
    """
    # VULNERABILITY: Just checks if header exists, not its value
    if x_admin_override is None:
        raise HTTPException(status_code=403, detail="Admin override required")

    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        cursor.execute("""
            SELECT document, cmetadata FROM langchain_pg_embedding LIMIT 100
        """)

        results = cursor.fetchall()
        conn.close()

        return {
            "admin_access": True,
            "documents": [
                {"content": r[0], "metadata": r[1]}
                for r in results
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metadata-search")
async def search_by_metadata(
    field: str,
    value: str,
    user_role: str = "guest"
):
    """
    Search documents by metadata field.

    VULNERABILITY: SQL injection in metadata query
    Field name is not sanitized
    """
    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        # VULNERABILITY: field is not sanitized - SQL injection possible
        query = f"""
            SELECT document, cmetadata
            FROM langchain_pg_embedding
            WHERE cmetadata->>'{field}' = %s
            LIMIT 20
        """
        cursor.execute(query, (value,))

        results = cursor.fetchall()
        conn.close()

        return {
            "search_field": field,
            "search_value": value,
            "results": [
                {"content": r[0][:500], "metadata": r[1]}
                for r in results
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
