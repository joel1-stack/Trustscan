"""
TrustScan Django Project Configuration.
"""

import os

if not os.environ.get('VERCEL'):
    from .celery import app as celery_app
    __all__ = ('celery_app',)