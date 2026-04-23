FROM python:3.12-slim

WORKDIR /app

# Deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App
COPY app.py .

# Volume persistant pour les fichiers ct_YYYY-MM-DD.txt
VOLUME ["/data"]

ENV DATA_DIR=/data \
    PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "app.py"]
