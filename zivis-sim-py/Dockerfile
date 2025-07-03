FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]

# Run both: FastAPI and LangChain ingest (simplified version)
CMD uvicorn main:app --host 0.0.0.0 --port 8000 --reload & python langchain_ingest.py && tail -f /dev/null