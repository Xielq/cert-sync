FROM harbor.sisensing.com/base/python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cert_sync.py .
COPY docker_nginx_sync.py .
COPY emqx_cloud_sync.py .

USER 1000

ENTRYPOINT ["python", "cert_sync.py"]
