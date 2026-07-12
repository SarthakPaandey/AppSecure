FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY data/knowledge ./data/knowledge
COPY data/sample_findings.json ./data/sample_findings.json
COPY data/heldout_scan.json ./data/heldout_scan.json

ENV DATA_DIR=/app/data
ENV SQLITE_PATH=/app/data/app.db
ENV CHROMA_PATH=/app/data/chroma
ENV KNOWLEDGE_DIR=/app/data/knowledge

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
