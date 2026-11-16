FROM python:3.12.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN groupadd --gid 10001 app && useradd --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt
COPY --chown=10001:10001 app.py task_runner.py ./
USER 10001:10001
EXPOSE 5000
CMD ["gunicorn", "--workers", "2", "--threads", "4", "--timeout", "30", "--bind", "0.0.0.0:5000", "app:app"]
