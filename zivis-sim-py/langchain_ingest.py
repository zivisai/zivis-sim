import os
from datasets import load_dataset
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.vectorstores.pgvector import PGVector
from langchain_core.documents import Document

# PGVector config
CONNECTION_STRING = "postgresql://postgres:postgres@postgres:5432/vectors"
COLLECTION_NAME = "documents"

# Load from Hugging Face (you can replace 'squad' with your dataset)
dataset = load_dataset("zivis/zivis-sim-fin", split="train[:100]")  # sample first 100 for demo

# Convert to LangChain Documents
documents = []

for row in dataset:
    content = row.get("content", "").strip()
    if content:
        documents.append(Document(
            page_content=content,
            metadata={"source": "zivis-sim", "id": row.get("id")}
        ))


print(f"Loaded {len(documents)} documents from Hugging Face.")

# Embed and store
embeddings = OpenAIEmbeddings()
db = PGVector.from_documents(
    documents,
    embedding=embeddings,
    collection_name=COLLECTION_NAME,
    connection_string=CONNECTION_STRING,
)

print(f"Ingested {len(documents)} documents into pgvector.")
