FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sentinel ./sentinel
COPY agents.json tool_permissions.json ./

EXPOSE 8001
CMD ["uvicorn", "sentinel.main:app", "--host", "0.0.0.0", "--port", "8001"]
