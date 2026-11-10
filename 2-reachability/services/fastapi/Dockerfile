FROM python:3.12-slim
RUN pip install --no-cache-dir fastapi==0.115.6 uvicorn==0.34.0
COPY app.py /app.py
CMD ["uvicorn", "app:app", "--app-dir", "/", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
