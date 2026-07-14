"""
WSGI config for TrustScan project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

application = get_wsgi_application()

if not os.environ.get('VERCEL'):
    from config.celery import app as celery_app
    __all__ = ('application', 'celery_app')