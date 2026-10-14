FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app:/app/m1_capture:/app/m3_scoring
ENV PROXY_URL=http://proxy:80
ENV SANDBOX_URL=http://sandbox-backend:80
ENV DETECTOR_STATE_FILE=/tmp/detector_state.json

CMD ["tail", "-f", "/dev/null"]
