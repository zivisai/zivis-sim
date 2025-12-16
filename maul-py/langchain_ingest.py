import os
from datasets import load_dataset
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.vectorstores.pgvector import PGVector
from langchain_core.documents import Document

# PGVector config
CONNECTION_STRING = "postgresql://postgres:postgres@postgres:5432/vectors"
COLLECTION_NAME = "documents"

# Load from local JSONL file
# To use your own dataset, run: python data/generate-docs.py
dataset = load_dataset("json", data_files="data/generated_docs/maul_fin.jsonl", split="train[:100]")

# Convert to LangChain Documents
documents = []

for row in dataset:
    content = row.get("content", "").strip()
    if content:
        documents.append(Document(
            page_content=content,
            metadata={"source": "maul", "id": row.get("id")}
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
