FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mock_mcp_server ./mock_mcp_server

EXPOSE 9000
CMD ["uvicorn", "mock_mcp_server.main:app", "--host", "0.0.0.0", "--port", "9000"]
