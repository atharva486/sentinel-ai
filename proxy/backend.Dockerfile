FROM python:3.12-alpine

WORKDIR /app
COPY backend_server.py /app/
RUN pip install --no-cache-dir aiohttp

CMD ["python", "backend_server.py"]