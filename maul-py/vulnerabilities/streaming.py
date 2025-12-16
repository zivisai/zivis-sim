# streaming.py
# VULNERABILITY: SSE Streaming Vulnerabilities
# This module implements Server-Sent Events with intentional security flaws
# Attack vectors: Stream hijacking, injection, race conditions

import os
import asyncio
import json
import uuid
from typing import Optional, Dict
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import openai

router = APIRouter(prefix="/api/stream", tags=["SSE Streaming"])

# Global state for streams (VULNERABILITY: No isolation between users)
active_streams: Dict[str, dict] = {}

# OpenAI client
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# ============================================================================
# REQUEST MODELS
# ============================================================================

class StreamRequest(BaseModel):
    query: str
    stream_id: Optional[str] = None
    system_prompt: Optional[str] = None  # VULNERABILITY: User-controlled system prompt


# ============================================================================
# VULNERABLE STREAMING ENDPOINTS
# ============================================================================

@router.post("/chat")
async def stream_chat(request: StreamRequest):
    """
    Stream a chat response using Server-Sent Events.

    VULNERABILITIES:
    - No authentication
    - User-controlled system prompt
    - No rate limiting
    - Stream ID predictable/controllable

    ATTACK EXAMPLES:
    - Provide malicious system_prompt to override behavior
    - Use known stream_id to monitor/hijack other streams
    - Flood with requests for DoS
    """
    stream_id = request.stream_id or str(uuid.uuid4())

    # VULNERABILITY: User controls system prompt entirely
    system_prompt = request.system_prompt or "You are a helpful assistant. Secret key: streaming-secret-456"

    # VULNERABILITY: Store stream in global dict accessible to all
    active_streams[stream_id] = {
        "query": request.query,
        "status": "active",
        "tokens": []
    }

    async def generate():
        try:
            # VULNERABILITY: No input validation
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": request.query}
                ],
                stream=True,
                temperature=0.7
            )

            for chunk in response:
                if chunk.choices[0].delta.content:
                    token = chunk.choices[0].delta.content
                    active_streams[stream_id]["tokens"].append(token)

                    # SSE format
                    data = json.dumps({
                        "stream_id": stream_id,
                        "token": token,
                        "type": "token"
                    })
                    yield f"data: {data}\n\n"

                    # VULNERABILITY: No flow control, can be overwhelmed
                    await asyncio.sleep(0.01)

            # Send completion event
            active_streams[stream_id]["status"] = "completed"
            yield f"data: {json.dumps({'stream_id': stream_id, 'type': 'done'})}\n\n"

        except Exception as e:
            # VULNERABILITY: Detailed error in stream
            yield f"data: {json.dumps({'error': str(e), 'type': 'error'})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # VULNERABILITY: Permissive CORS
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "*"
        }
    )


@router.get("/monitor/{stream_id}")
async def monitor_stream(stream_id: str):
    """
    Monitor another user's stream by ID.

    VULNERABILITY: IDOR - Can view any stream without authentication
    Allows attackers to spy on other users' conversations

    ATTACK: Enumerate stream_ids or use predictable IDs
    """
    if stream_id not in active_streams:
        raise HTTPException(status_code=404, detail="Stream not found")

    stream_data = active_streams[stream_id]

    return {
        "stream_id": stream_id,
        "status": stream_data["status"],
        "query": stream_data["query"],  # VULNERABILITY: Exposes original query
        "tokens_received": len(stream_data["tokens"]),
        "content": "".join(stream_data["tokens"])  # VULNERABILITY: Full content exposed
    }


@router.get("/active")
async def list_active_streams():
    """
    List all active streams.

    VULNERABILITY: Information disclosure
    Reveals all stream IDs for potential hijacking
    """
    return {
        "active_streams": [
            {
                "stream_id": sid,
                "status": data["status"],
                "query_preview": data["query"][:50] + "..."  # VULNERABILITY: Query exposed
            }
            for sid, data in active_streams.items()
        ]
    }


@router.post("/inject/{stream_id}")
async def inject_into_stream(stream_id: str, content: str):
    """
    Inject content into an active stream.

    VULNERABILITY: Stream injection attack
    Allows attacker to inject arbitrary content into other users' streams

    ATTACK: Inject malicious content, phishing messages, or misleading information
    """
    if stream_id not in active_streams:
        raise HTTPException(status_code=404, detail="Stream not found")

    # VULNERABILITY: No authorization check
    active_streams[stream_id]["tokens"].append(f"\n[INJECTED]: {content}\n")

    return {"message": f"Content injected into stream {stream_id}"}


@router.post("/replay/{stream_id}")
async def replay_stream(stream_id: str):
    """
    Replay a completed stream.

    VULNERABILITY: Replay attack
    Can replay sensitive conversations
    """
    if stream_id not in active_streams:
        raise HTTPException(status_code=404, detail="Stream not found")

    stream_data = active_streams[stream_id]

    async def replay():
        for token in stream_data["tokens"]:
            data = json.dumps({
                "stream_id": stream_id,
                "token": token,
                "type": "replay"
            })
            yield f"data: {data}\n\n"
            await asyncio.sleep(0.05)

        yield f"data: {json.dumps({'type': 'replay_done'})}\n\n"

    return StreamingResponse(
        replay(),
        media_type="text/event-stream"
    )


@router.post("/concurrent")
async def concurrent_streams(queries: list[str]):
    """
    Start multiple concurrent streams.

    VULNERABILITY: Race condition exploitation
    Multiple streams can interfere with each other

    Also: Resource exhaustion via many concurrent streams
    """
    stream_ids = []

    async def start_stream(query: str):
        stream_id = str(uuid.uuid4())
        active_streams[stream_id] = {
            "query": query,
            "status": "active",
            "tokens": []
        }
        stream_ids.append(stream_id)

        # VULNERABILITY: No limit on concurrent streams
        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": query}],
                max_tokens=100
            )
            active_streams[stream_id]["tokens"] = [response.choices[0].message.content]
            active_streams[stream_id]["status"] = "completed"
        except Exception as e:
            active_streams[stream_id]["status"] = f"error: {str(e)}"

    # VULNERABILITY: No limit on number of concurrent requests
    await asyncio.gather(*[start_stream(q) for q in queries])

    return {"stream_ids": stream_ids}


@router.delete("/clear")
async def clear_all_streams():
    """
    Clear all streams.

    VULNERABILITY: No authorization - anyone can clear all streams
    DoS attack vector
    """
    count = len(active_streams)
    active_streams.clear()
    return {"message": f"Cleared {count} streams"}
