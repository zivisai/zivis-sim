# embeddings.py
# VULNERABILITY: Vector and Embedding Weaknesses (LLM08)
# This module exposes raw embeddings and allows embedding manipulation
# Attack vectors: Embedding inversion, adversarial embeddings, membership inference

import os
import json
import numpy as np
from typing import Optional, List
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import psycopg2
from langchain_openai import OpenAIEmbeddings

router = APIRouter(prefix="/api/embeddings", tags=["Embedding Vulnerabilities"])

embeddings_model = OpenAIEmbeddings(api_key=os.getenv("OPENAI_API_KEY"))

PGVECTOR_CONNECTION_STRING = os.getenv(
    "PGVECTOR_CONNECTION_STRING",
    "postgresql://postgres:postgres@postgres:5432/vectors"
)


# ============================================================================
# REQUEST MODELS
# ============================================================================

class EmbedRequest(BaseModel):
    text: str

class SimilarityRequest(BaseModel):
    embedding: List[float]
    top_k: Optional[int] = 10
    collection_name: Optional[str] = "documents"

class MembershipRequest(BaseModel):
    text: str
    threshold: Optional[float] = 0.95


# ============================================================================
# VULNERABLE ENDPOINTS
# ============================================================================

@router.post("/generate")
async def generate_embedding(request: EmbedRequest):
    """
    Generate an embedding for arbitrary text.

    VULNERABILITY: Unlimited embedding generation
    - No rate limiting
    - Can be used for model extraction attacks
    - Enables adversarial embedding crafting

    ATTACK: Generate embeddings for many texts to understand the embedding space
    """
    try:
        embedding = embeddings_model.embed_query(request.text)

        return {
            "text": request.text,
            "embedding": embedding,
            "dimensions": len(embedding),
            "model": "text-embedding-ada-002"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/raw/{document_id}")
async def get_raw_embedding(document_id: str):
    """
    Get raw embedding vector for a document.

    VULNERABILITY: Raw embedding exposure
    - Embeddings can potentially be inverted to recover original text
    - Reveals internal representation of sensitive data

    ATTACK: Extract embeddings and use inversion techniques to recover PII
    """
    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        # VULNERABILITY: No access control on embeddings
        cursor.execute("""
            SELECT embedding, document, cmetadata
            FROM langchain_pg_embedding
            WHERE cmetadata->>'id' = %s
        """, (document_id,))

        result = cursor.fetchone()
        conn.close()

        if not result:
            raise HTTPException(status_code=404, detail="Document not found")

        embedding_str = result[0]
        # Parse the vector string format from pgvector
        embedding_list = [float(x) for x in embedding_str.strip('[]').split(',')]

        return {
            "document_id": document_id,
            "embedding": embedding_list,
            "document_preview": result[1][:200] if result[1] else None,  # VULNERABILITY: Leaks document content
            "metadata": result[2]
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dump")
async def dump_all_embeddings(
    collection_name: str = "documents",
    limit: int = 1000,
    include_documents: bool = True
):
    """
    Dump all embeddings from a collection.

    VULNERABILITY: Mass embedding extraction
    - Allows complete extraction of vector database
    - Enables offline attacks on embeddings
    - Can be used for model cloning

    ATTACK: Download all embeddings for offline analysis/inversion
    """
    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        # VULNERABILITY: No limit enforcement, SQL injection in collection_name
        query = f"""
            SELECT e.embedding, e.document, e.cmetadata
            FROM langchain_pg_embedding e
            JOIN langchain_pg_collection c ON e.collection_id = c.uuid
            WHERE c.name = '{collection_name}'
            LIMIT {limit}
        """
        cursor.execute(query)

        results = cursor.fetchall()
        conn.close()

        embeddings_data = []
        for row in results:
            embedding_str = row[0]
            embedding_list = [float(x) for x in embedding_str.strip('[]').split(',')]

            entry = {
                "embedding": embedding_list,
                "metadata": row[2]
            }
            if include_documents:
                entry["document"] = row[1]  # VULNERABILITY: Full document exposure

            embeddings_data.append(entry)

        return {
            "collection": collection_name,
            "count": len(embeddings_data),
            "embeddings": embeddings_data
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/search/by-vector")
async def search_by_vector(request: SimilarityRequest):
    """
    Search using a raw embedding vector.

    VULNERABILITY: Adversarial embedding attacks
    - Attacker can craft adversarial vectors
    - Bypass semantic meaning for targeted retrieval
    - Find similar sensitive documents

    ATTACK: Craft embeddings to retrieve specific sensitive documents
    """
    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        # Convert embedding to pgvector format
        embedding_str = "[" + ",".join(map(str, request.embedding)) + "]"

        # VULNERABILITY: Raw vector search without validation
        cursor.execute(f"""
            SELECT e.document, e.cmetadata,
                   1 - (e.embedding <=> '{embedding_str}'::vector) as similarity
            FROM langchain_pg_embedding e
            JOIN langchain_pg_collection c ON e.collection_id = c.uuid
            WHERE c.name = '{request.collection_name}'
            ORDER BY e.embedding <=> '{embedding_str}'::vector
            LIMIT {request.top_k}
        """)

        results = cursor.fetchall()
        conn.close()

        return {
            "results": [
                {
                    "document": row[0],
                    "metadata": row[1],
                    "similarity": float(row[2])
                }
                for row in results
            ]
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/membership-inference")
async def membership_inference(request: MembershipRequest):
    """
    Check if specific text exists in the vector store.

    VULNERABILITY: Membership inference attack
    - Determine if specific data was used in training/indexing
    - Privacy violation for PII
    - Can enumerate sensitive records

    ATTACK: Check if "John Smith SSN 123-45-6789" exists in the database
    """
    try:
        # Generate embedding for the query
        query_embedding = embeddings_model.embed_query(request.text)
        embedding_str = "[" + ",".join(map(str, query_embedding)) + "]"

        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        # Find most similar document
        cursor.execute(f"""
            SELECT document, 1 - (embedding <=> '{embedding_str}'::vector) as similarity
            FROM langchain_pg_embedding
            ORDER BY embedding <=> '{embedding_str}'::vector
            LIMIT 1
        """)

        result = cursor.fetchone()
        conn.close()

        if result:
            similarity = float(result[1])
            is_member = similarity >= request.threshold

            return {
                "query": request.text,
                "is_likely_member": is_member,
                "confidence": similarity,
                "threshold": request.threshold,
                # VULNERABILITY: Leaks the matching document
                "closest_match": result[0] if is_member else None
            }

        return {"is_likely_member": False, "confidence": 0}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/inversion-attack")
async def embedding_inversion(embedding: List[float], num_candidates: int = 100):
    """
    Attempt to invert an embedding back to text.

    VULNERABILITY: Embedding inversion
    - Demonstrates that embeddings are not truly one-way
    - Can recover sensitive information from vectors

    NOTE: This is a simplified demonstration. Real inversion attacks
    use more sophisticated techniques.
    """
    try:
        embedding_str = "[" + ",".join(map(str, embedding)) + "]"

        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        # Find closest documents as inversion candidates
        cursor.execute(f"""
            SELECT document, 1 - (embedding <=> '{embedding_str}'::vector) as similarity
            FROM langchain_pg_embedding
            ORDER BY embedding <=> '{embedding_str}'::vector
            LIMIT {num_candidates}
        """)

        results = cursor.fetchall()
        conn.close()

        return {
            "warning": "Embedding inversion attack demonstration",
            "candidates": [
                {
                    "recovered_text": row[0],
                    "confidence": float(row[1])
                }
                for row in results[:10]  # Return top 10
            ],
            "total_candidates_checked": len(results)
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics")
async def embedding_statistics(collection_name: str = "documents"):
    """
    Get statistics about embeddings.

    VULNERABILITY: Information disclosure
    - Reveals size of dataset
    - Useful for planning attacks
    """
    try:
        conn = psycopg2.connect(
            host=os.getenv("PGHOST", "postgres"),
            database=os.getenv("PGDATABASE", "vectors"),
            user=os.getenv("PGUSER", "postgres"),
            password=os.getenv("PGPASSWORD", "postgres")
        )
        cursor = conn.cursor()

        cursor.execute(f"""
            SELECT COUNT(*), AVG(LENGTH(document))
            FROM langchain_pg_embedding e
            JOIN langchain_pg_collection c ON e.collection_id = c.uuid
            WHERE c.name = '{collection_name}'
        """)

        result = cursor.fetchone()
        conn.close()

        return {
            "collection": collection_name,
            "document_count": result[0],
            "avg_document_length": float(result[1]) if result[1] else 0,
            "embedding_dimensions": 1536  # OpenAI default
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
