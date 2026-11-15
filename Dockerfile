ARG PYTHON_IMAGE=python:3.12.12-slim-bookworm
FROM ${PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py test_runtime.py ./
COPY assets/icon.png /app/static/icon.png
RUN mkdir /data && chown -R 1000:1000 /data /app
USER 1000:1000
EXPOSE 8080
CMD ["sh", "-c", "python -c 'import app; app.quarantine_interrupted_approvals()' && exec gunicorn --bind 0.0.0.0:8080 --workers 2 --threads 2 --timeout 45 --access-logfile - app:app"]
