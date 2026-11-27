FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY local_oauth.py setup_oauth.py client.py server.py bootstrap_device.py /app/

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin app \
    && mkdir -p /data /config \
    && chown 10001:10001 /data

USER 10001:10001

EXPOSE 8787

CMD ["python", "server.py"]
