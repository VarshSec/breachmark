FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV BREACHMARK_HOST=0.0.0.0 BREACHMARK_PORT=8000 BREACHMARK_DB=/data/breachmark.db BREACHMARK_ALLOWED_HOSTS=*
# Ollama on the host: run with --add-host=host.docker.internal:host-gateway -e OLLAMA_HOST=http://host.docker.internal:11434
VOLUME ["/data"]
EXPOSE 8000
CMD ["python", "-m", "breachmark", "serve"]
