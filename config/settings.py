"""
Django settings for TrustScan project.
"""

from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-dev-key-change-in-production')

DEBUG = os.getenv('DEBUG', 'True').lower() == 'true'

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1,.vercel.app,.onrender.com,*.northflank.app').split(',')

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    'rest_framework',
    'rest_framework.authtoken',
    'django_filters',
    'corsheaders',
    'celery',
    'drf_spectacular',
    
    'apps.core',
    'apps.accounts',
    'apps.domains',
    'apps.scanner',
    'apps.discovery',
    'apps.reconnaissance',
    'apps.correlation',
    'apps.scoring',
    'apps.intelligence',
    'apps.reports',
    'apps.billing',
    'apps.api',
    'apps.dashboard',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'
ASGI_APPLICATION = 'config.asgi.application'

_db_engine = os.getenv('DB_ENGINE') or 'django.db.backends.sqlite3'
if _db_engine == 'django.db.backends.sqlite3':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': Path('/tmp/db.sqlite3') if (os.environ.get('VERCEL') or os.environ.get('NORTHFLANK')) else BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': _db_engine,
            'NAME': os.getenv('DB_NAME', 'trustscan'),
            'USER': os.getenv('DB_USER', 'trustscan'),
            'PASSWORD': os.getenv('DB_PASSWORD', 'trustscan'),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Nairobi'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'accounts.User'
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
        'apps.api.authentication.APIKeyAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.OrderingFilter',
        'rest_framework.filters.SearchFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'EXCEPTION_HANDLER': 'apps.core.exceptions.custom_exception_handler',
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'TrustScan API',
    'DESCRIPTION': 'Digital Trust Intelligence Platform API',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
}

CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/1')
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 30 * 60
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Africa/Nairobi'
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers:DatabaseScheduler'

CELERY_TASK_ROUTES = {
    'apps.discovery.workers.*': {'queue': 'discovery'},
    'apps.reconnaissance.workers.*': {'queue': 'reconnaissance'},
    'apps.correlation.workers.*': {'queue': 'correlation'},
    'apps.scoring.workers.*': {'queue': 'scoring'},
    'apps.intelligence.workers.*': {'queue': 'intelligence'},
    'apps.reports.workers.*': {'queue': 'reporting'},
    'apps.billing.workers.*': {'queue': 'billing'},
    'apps.scanner.tasks.*': {'queue': 'orchestration'},
}

CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.getenv('REDIS_URL', 'redis://localhost:6379/2'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'

EMAIL_BACKEND = os.getenv('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'TrustScan <noreply@trustscan.co.ke>')

MPESA_CONSUMER_KEY = os.getenv('MPESA_CONSUMER_KEY', '')
MPESA_CONSUMER_SECRET = os.getenv('MPESA_CONSUMER_SECRET', '')
MPESA_SHORTCODE = os.getenv('MPESA_SHORTCODE', '')
MPESA_PASSKEY = os.getenv('MPESA_PASSKEY', '')
MPESA_CALLBACK_URL = os.getenv('MPESA_CALLBACK_URL', '')
MPESA_ENVIRONMENT = os.getenv('MPESA_ENVIRONMENT', 'sandbox')

SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
HIBP_API_KEY = os.getenv('HIBP_API_KEY', '')
DEHASHED_API_KEY = os.getenv('DEHASHED_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
SPAMHAUS_API_KEY = os.getenv('SPAMHAUS_API_KEY', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
BUILTWITH_API_KEY = os.getenv('BUILTWITH_API_KEY', '')
SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', '')

TRUSTSCAN_SCAN_TIMEOUT = int(os.getenv('TRUSTSCAN_SCAN_TIMEOUT', 300))
TRUSTSCAN_MAX_SUBDOMAINS = int(os.getenv('TRUSTSCAN_MAX_SUBDOMAINS', 500))
TRUSTSCAN_RATE_LIMIT_PER_HOUR = int(os.getenv('TRUSTSCAN_RATE_LIMIT_PER_HOUR', 10))

_on_vercel = bool(os.environ.get('VERCEL'))
_on_northflank = bool(os.environ.get('NORTHFLANK'))
_logs_dir = Path('/tmp/logs') if (_on_vercel or _on_northflank) else BASE_DIR / 'logs'
_logs_writable = _logs_dir.exists()
if not _logs_dir.exists():
    try:
        _logs_dir.mkdir(parents=True, exist_ok=True)
        _logs_writable = True
    except OSError:
        _logs_writable = False

_handlers = {
    'console': {
        'level': 'DEBUG',
        'class': 'logging.StreamHandler',
        'formatter': 'simple',
    },
}

_loggers_root_handlers = ['console']
_loggers_map = {}

if _logs_writable:
    _handlers['file'] = {
        'level': 'INFO',
        'class': 'logging.handlers.RotatingFileHandler',
        'filename': _logs_dir / 'scanner.log',
        'maxBytes': 1024 * 1024 * 10,
        'backupCount': 5,
        'formatter': 'verbose',
    }
    _handlers['celery_file'] = {
        'level': 'INFO',
        'class': 'logging.handlers.RotatingFileHandler',
        'filename': _logs_dir / 'celery.log',
        'maxBytes': 1024 * 1024 * 10,
        'backupCount': 5,
        'formatter': 'verbose',
    }
    _handlers['api_file'] = {
        'level': 'INFO',
        'class': 'logging.handlers.RotatingFileHandler',
        'filename': _logs_dir / 'api.log',
        'maxBytes': 1024 * 1024 * 10,
        'backupCount': 5,
        'formatter': 'verbose',
    }
    _loggers_root_handlers = ['console', 'file']
    _loggers_map = {
        'apps': {'handlers': ['console', 'file'], 'level': 'INFO', 'propagate': False},
        'celery': {'handlers': ['console', 'celery_file'], 'level': 'INFO', 'propagate': False},
        'api': {'handlers': ['console', 'api_file'], 'level': 'INFO', 'propagate': False},
        'django': {'handlers': ['console', 'file'], 'level': 'INFO', 'propagate': False},
    }

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': _handlers,
    'root': {
        'handlers': _loggers_root_handlers,
        'level': 'INFO',
    },
    'loggers': _loggers_map,
}

CSRF_TRUSTED_ORIGINS = os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',') if os.getenv('CSRF_TRUSTED_ORIGINS') else []

CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000').split(',')
CORS_ALLOW_CREDENTIALS = True

SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

TRUSTSCAN_SCORING_VERSION = '2026.1'
TRUSTSCAN_DIMENSION_WEIGHTS = {
    'email_security': 0.20,
    'infrastructure_hygiene': 0.15,
    'exposure_surface': 0.15,
    'breach_history': 0.15,
    'reputation_trust': 0.15,
    'identity_integrity': 0.20,
}