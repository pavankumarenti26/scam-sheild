FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV XDG_CACHE_HOME=/root/.cache

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/backend/requirements.txt

RUN pip install --upgrade pip && \
    pip install torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install -r /app/backend/requirements.txt

RUN python -c "import whisper; whisper.load_model('base')"

COPY backend/ /app/backend/
COPY frontend/ /app/frontend/

EXPOSE 10000

CMD ["sh", "-c", "uvicorn app:app --app-dir /app/backend --host 0.0.0.0 --port ${PORT:-10000}"]
