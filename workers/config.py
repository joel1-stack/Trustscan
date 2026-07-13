from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'schedule-recurring-scans': {
        'task': 'apps.scanner.tasks.schedule_recurring_scans',
        'schedule': crontab(minute='*/5'),
    },
    'cleanup-stale-scan-jobs': {
        'task': 'apps.scanner.tasks.cleanup_stale_scan_jobs',
        'schedule': crontab(minute='*/10'),
    },
    'retry-failed-scans': {
        'task': 'apps.scanner.tasks.retry_failed_scans',
        'schedule': crontab(minute=0, hour='*/6'),
    },
    'generate-invoices': {
        'task': 'apps.billing.workers.generate_invoices',
        'schedule': crontab(minute=0, hour=2),
    },
    'process-recurring-payments': {
        'task': 'apps.billing.workers.process_recurring_payments',
        'schedule': crontab(minute=30, hour=2),
    },
    'send-payment-reminders': {
        'task': 'apps.billing.workers.send_payment_reminders',
        'schedule': crontab(minute=0, hour=9),
    },
    'update-usage-records': {
        'task': 'apps.billing.workers.update_usage_records',
        'schedule': crontab(minute=0, hour=1),
    },
    'check-subscription-limits': {
        'task': 'apps.billing.workers.check_subscription_limits',
        'schedule': crontab(minute=0, hour=3),
    },
    'handle-failed-payments': {
        'task': 'apps.billing.workers.handle_failed_payments',
        'schedule': crontab(minute=0, hour=4),
    },
    'update-benchmarks': {
        'task': 'apps.intelligence.workers.update_benchmarks',
        'schedule': crontab(minute=0, hour=3),
    },
    'update-threat-intel': {
        'task': 'apps.intelligence.workers.update_threat_intel',
        'schedule': crontab(minute=0, hour='*/6'),
    },
    'update-cve-feed': {
        'task': 'apps.intelligence.workers.update_cve_feed',
        'schedule': crontab(minute=0, hour=4),
    },
    'process-scheduled-reports': {
        'task': 'apps.reports.workers.process_scheduled_reports',
        'schedule': crontab(minute=0, hour='*'),
    },
    'cleanup-old-reports': {
        'task': 'apps.reports.workers.cleanup_old_reports',
        'schedule': crontab(minute=0, hour=5),
    },
    'cleanup-old-api-logs': {
        'task': 'apps.api.tasks.cleanup_old_api_logs',
        'schedule': crontab(minute=0, hour=6),
    },
}

CELERY_TASK_ROUTES = {
    'apps.scanner.tasks.*': {'queue': 'orchestration'},
    'apps.discovery.workers.*': {'queue': 'discovery'},
    'apps.reconnaissance.workers.*': {'queue': 'reconnaissance'},
    'apps.correlation.workers.*': {'queue': 'correlation'},
    'apps.scoring.workers.*': {'queue': 'scoring'},
    'apps.intelligence.workers.*': {'queue': 'intelligence'},
    'apps.reports.workers.*': {'queue': 'reporting'},
    'apps.billing.workers.*': {'queue': 'billing'},
    'apps.api.tasks.*': {'queue': 'api'},
    'apps.domains.tasks.*': {'queue': 'domains'},
    'apps.accounts.tasks.*': {'queue': 'accounts'},
}

CELERY_TASK_QUEUES = {
    'orchestration': {},
    'discovery': {},
    'reconnaissance': {},
    'correlation': {},
    'scoring': {},
    'intelligence': {},
    'reporting': {},
    'billing': {},
    'api': {},
    'domains': {},
    'accounts': {},
    'default': {},
}

CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_MAX_TASKS_PER_CHILD = 1000
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_TASK_TIME_LIMIT = 30 * 60
CELERY_TASK_SOFT_TIME_LIMIT = 25 * 60
CELERY_RESULT_EXPIRES = 3600
CELERY_RESULT_COMPRESSION = 'gzip'
CELERY_TASK_COMPRESSION = 'gzip'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'Africa/Nairobi'
CELERY_ENABLE_UTC = True