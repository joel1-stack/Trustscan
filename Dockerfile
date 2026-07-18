# v2 - moved auth to /auth/ prefix to avoid SnapDeploy interception
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock || true

COPY . .

ENV DJANGO_SETTINGS_MODULE=config.settings
ENV DEBUG=False
ENV ALLOWED_HOSTS=*
ENV SECRET_KEY=django-insecure-prod-key-change-in-production
ENV DATABASE_URL=postgresql://postgres:oGftHn0JoqZWAZJp@db.rzqryyarxezmsspudmxv.supabase.co:6543/postgres
ENV REDIS_URL=rediss://default:gQAAAAAAAR0wAAIgcDI3NDE3ZTZkZDk1ZGE0NTg1YjBiOTlkNmMzNzI5MTlkNw@pleasing-muskox-73008.upstash.io:6379?ssl_cert_reqs=CERT_REQUIRED
ENV CELERY_BROKER_URL=rediss://default:gQAAAAAAAR0wAAIgcDI3NDE3ZTZkZDk1ZGE0NTg1YjBiOTlkNmMzNzI5MTlkNw@pleasing-muskox-73008.upstash.io:6379?ssl_cert_reqs=CERT_REQUIRED
ENV CELERY_RESULT_BACKEND=rediss://default:gQAAAAAAAR0wAAIgcDI3NDE3ZTZkZDk1ZGE0NTg1YjBiOTlkNmMzNzI5MTlkNw@pleasing-muskox-73008.upstash.io:6379?ssl_cert_reqs=CERT_REQUIRED

RUN adduser --disabled-password --no-create-home appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput 2>&1 | tail -5 & gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 1 --timeout 120 & celery -A config worker --loglevel=info --concurrency=1 & wait"]
