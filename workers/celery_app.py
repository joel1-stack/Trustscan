import os
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

app = Celery('trustscan')

app.config_from_object('django.conf:settings', namespace='CELERY')

app.autodiscover_tasks([
    'apps.scanner',
    'apps.discovery',
    'apps.reconnaissance',
    'apps.correlation',
    'apps.scoring',
    'apps.intelligence',
    'apps.reports',
    'apps.billing',
    'apps.api',
    'apps.accounts',
    'apps.domains',
])

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Africa/Nairobi',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,
    task_soft_time_limit=25 * 60,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    broker_connection_retry_on_startup=True,
    broker_connection_retry=True,
    broker_connection_max_retries=10,
    result_expires=3600,
    result_compression='gzip',
    task_compression='gzip',
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_default_queue='default',
    task_routes={
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
    },
    beat_schedule={
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
            'schedule': crontab(minute=0, hour=5),
        },
        'update-threat-intel': {
            'task': 'apps.intelligence.workers.update_threat_intel',
            'schedule': crontab(minute=30, hour=5),
        },
        'update-cve-feed': {
            'task': 'apps.intelligence.workers.update_cve_feed',
            'schedule': crontab(minute=0, hour=6),
        },
        'process-scheduled-reports': {
            'task': 'apps.reports.workers.process_scheduled_reports',
            'schedule': crontab(minute=0, hour=7),
        },
        'cleanup-old-reports': {
            'task': 'apps.reports.workers.cleanup_old_reports',
            'schedule': crontab(minute=0, hour=8, day_of_month=1),
        },
        'cleanup-old-api-logs': {
            'task': 'apps.api.tasks.cleanup_old_api_logs',
            'schedule': crontab(minute=0, hour=9, day_of_month=1),
        },
        'cleanup-old-correlations': {
            'task': 'apps.correlation.workers.cleanup_old_correlations',
            'schedule': crontab(minute=0, hour=10, day_of_month=1),
        },
    },
)

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')


app.conf.beat_scheduler = 'django_celery_beat.schedulers:DatabaseScheduler'