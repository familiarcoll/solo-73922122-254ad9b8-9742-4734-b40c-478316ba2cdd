FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector ./collector
COPY source ./source
COPY forbidden ./forbidden
COPY dns ./dns

EXPOSE 8000
CMD ["uvicorn", "collector.main:app", "--host", "0.0.0.0", "--port", "8000"]
