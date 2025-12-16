FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYDEVD_DISABLE_FILE_VALIDATION=1

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt debugpy
COPY . .

RUN chmod +x ./entrypoint.sh

EXPOSE 8000 5678

ENTRYPOINT ["./entrypoint.sh"]
