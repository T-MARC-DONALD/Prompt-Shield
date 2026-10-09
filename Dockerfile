# PromptShield Guard Server
FROM python:3.12-slim

WORKDIR /app

# The guard needs only Flask + CORS (defenses/ is stdlib-only).
RUN pip install --no-cache-dir "flask>=3.0.0" "flask-cors>=4.0.0"

COPY defenses/ ./defenses/
COPY guard_server.py .

EXPOSE 8090
ENV GUARD_HOST=0.0.0.0 GUARD_PORT=8090

CMD ["python", "guard_server.py"]
