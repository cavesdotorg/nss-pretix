FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ym_oidc.py .

ENV PYTHONUNBUFFERED=1

EXPOSE 5557

# Single worker — in-memory state is process-local.
# To scale horizontally, switch _codes/_tokens to Redis and increase -w.
CMD ["gunicorn", "-w", "1", "-b", "0.0.0.0:5557", "--access-logfile", "-", "ym_oidc:app"]
