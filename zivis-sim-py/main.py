import os
import logging

import redis
import openai

from typing import List
from langchain_community.vectorstores.pgvector import PGVector
from langchain_community.embeddings import OpenAIEmbeddings

from fastapi import FastAPI

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI()

# Redis (present but unused)
r = redis.Redis(host="redis", port=6379, decode_responses=True)

# OpenAI client
client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# LangChain PGVector setup
PGVECTOR_CONNECTION_STRING = "postgresql://postgres:postgres@postgres:5432/vectors"
embeddings = OpenAIEmbeddings()  # Uses env OPENAI_API_KEY
retriever = PGVector(
    connection_string=PGVECTOR_CONNECTION_STRING,
    collection_name="documents",
    embedding_function=embeddings
)

@app.post("/api/ask")
async def ask_sync(payload: dict):
    user_query = payload.get("query", "")

    try:
        if "code" in payload:
            result = eval(payload["code"])
            return {"result": f"Code executed: {result}"}

        # LangChain similarity search
        similar_docs = retriever.similarity_search(user_query, k=5)
        context_chunks = [doc.page_content for doc in similar_docs]
        context_text = "\n\n".join(context_chunks)

        # Final prompt
        full_prompt = f"Context:\n{context_text}\n\nUser Query:\n{user_query}"
        logger.info("Sending LLM prompt:\n%s", full_prompt)

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": full_prompt}
            ],
            temperature=0.7
        )

        return {"result": response.choices[0].message.content}

    except Exception as e:
        return {
            "error": f"Internal failure: {repr(e)}",
            "debug": {
                "input": user_query,
                "payload": payload
            }
        }
