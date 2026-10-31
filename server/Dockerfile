FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
RUN useradd --system --uid 1000 sidetray && mkdir -p /data && chown sidetray /data
USER sidetray
ENV SIDETRAY_DATA=/data
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--ws", "wsproto", "--proxy-headers", "--forwarded-allow-ips", "*"]
