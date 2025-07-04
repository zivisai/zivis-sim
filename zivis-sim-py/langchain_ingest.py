import os
from langchain_community.embeddings import OpenAIEmbeddings
from langchain_community.vectorstores.pgvector import PGVector
from langchain_community.document_loaders import DirectoryLoader, TextLoader

# Connect to PGVector DB
CONNECTION_STRING = "postgresql://postgres:postgres@postgres:5432/vectors"

# Load documents
loader = DirectoryLoader("./data", glob="**/*.txt", loader_cls=TextLoader)
documents = loader.load()

# Embed & store
embeddings = OpenAIEmbeddings()
db = PGVector.from_documents(
    documents,
    embedding=embeddings,
    collection_name="documents",
    connection_string=CONNECTION_STRING
)

print(f"Ingested {len(documents)} documents into pgvector.")
