import os
import psycopg2
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores.pgvector import PGVector
from langchain.document_loaders import DirectoryLoader, TextLoader

# Connect to PGVector DB
CONNECTION_STRING = "postgresql://postgres:postgres@postgres:5432/vectors"

# Load documents
loader = DirectoryLoader("documents", glob="*.txt", loader_cls=TextLoader)
documents = loader.load()

# Embed & store
embeddings = OpenAIEmbeddings()  # Uses OPENAI_API_KEY from env
db = PGVector.from_documents(
    documents,
    embedding=embeddings,
    collection_name="documents",
    connection_string=CONNECTION_STRING
)

print(f"Ingested {len(documents)} documents into pgvector.")
