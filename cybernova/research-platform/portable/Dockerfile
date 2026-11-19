# Cybernova portable, unprivileged, local-first deployment.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app
WORKDIR /app

COPY cybernova/research-platform/console/requirements.txt /tmp/cybernova-requirements.txt
RUN pip install --no-cache-dir -r /tmp/cybernova-requirements.txt && \
    groupadd -g 10001 cybernova && \
    useradd -M -u 10001 -g 10001 -s /usr/sbin/nologin cybernova && \
    mkdir -p /data /app/tool_gateway && chown -R 10001:10001 /data

COPY cybernova/research-platform/console /app/console
COPY cybernova/qwen-webui/mcp-gateway/core.py /app/tool_gateway/core.py
COPY cybernova/qwen-webui/mcp-gateway/http_client.py /app/tool_gateway/http_client.py
COPY cybernova/research-platform/portable/empty_scope.json /app/tool_gateway/scope.json

USER 10001:10001
EXPOSE 18795
HEALTHCHECK --interval=30s --timeout=12s --start-period=40s --retries=3 \
  CMD python -m console.portable_runtime doctor
CMD ["python","-m","console.portable_runtime"]
