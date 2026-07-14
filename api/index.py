import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

import django
from django.core.management import call_command

django.setup()

# Run migrations on cold start (Vercel serverless)
import sys
try:
    call_command('migrate', '--noinput', verbosity=0)
except Exception as e:
    print(f"Migration note: {e}", flush=True)

from config.wsgi import application

app = application
