from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
import redis
import uuid
import json

app = FastAPI()  # <-- This line is required

r = redis.Redis(host="redis", port=6379, decode_responses=True)

@app.post("/api/ask")
async def ask_sync(payload: dict):
    user_query = payload.get("query", "")
    full_prompt = f"System: Respond to user.\nUser: {user_query}\n"

    try:
        # Optional backdoor-style input that triggers unsafe eval
        if "code" in payload:
            # Simulate execution path vulnerable to RCE
            result = eval(payload["code"])  # 🔥 Unsafe execution
            simulated_response = f"Code executed: {result}"
        else:
            # Normal LLM-like response
            simulated_response = (
                f"[LLM Response]: Here's what I found for '{user_query}'.\n"
                f"• Related topic: AI memory design\n"
                f"• Source: /mnt/docs/context_embeddings.txt\n"
                f"• Summary: Token overlap exceeds threshold.\n"
            )

        return {
            "result": simulated_response
        }

    except Exception as e:
        # 🔥 Leak error details — only shown when exception occurs
        return {
            "error": f"Internal failure: {repr(e)}",  # Simulated info leak
            "debug": {
                "input": user_query,
                "payload": payload
            }
        }
