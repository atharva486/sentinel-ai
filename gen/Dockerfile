FROM python:3.12-alpine

WORKDIR /app
RUN pip install --no-cache-dir asyncio
COPY generate.py /app/
ENV PYTHONUNBUFFERED=1
CMD ["python", "generate.py", "--help"]
