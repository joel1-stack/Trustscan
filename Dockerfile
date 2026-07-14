FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DJANGO_SETTINGS_MODULE=config.settings

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir psycopg2-binary gunicorn

COPY . .

EXPOSE 8080

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py collectstatic --noinput --clear && gunicorn config.wsgi:application --bind 0.0.0.0:8080 --workers 4 --timeout 120"]
