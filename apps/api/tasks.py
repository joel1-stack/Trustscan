from celery import shared_task
from django.utils import timezone
from django.conf import settings
import requests
import hmac
import hashlib
import json
import logging

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=5, default_retry_delay=60)
def send_webhook(self, webhook_id: str, event_type: str, payload: dict):
    from apps.api.models import WebhookEndpoint, WebhookDelivery
    
    try:
        webhook = WebhookEndpoint.objects.get(id=webhook_id, is_active=True)
    except WebhookEndpoint.DoesNotExist:
        logger.warning(f"Webhook {webhook_id} not found or inactive")
        return {'status': 'skipped', 'reason': 'webhook_not_found'}
    
    if event_type not in webhook.events and '*' not in webhook.events:
        return {'status': 'skipped', 'reason': 'event_not_subscribed'}
    
    delivery = WebhookDelivery.objects.create(
        webhook=webhook,
        event_type=event_type,
        payload=payload,
        status='pending',
    )
    
    for attempt in range(1, 6):
        delivery.attempts = attempt
        delivery.save(update_fields=['attempts'])
        
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'TrustScan-Webhook/1.0',
            }
            
            if webhook.secret:
                signature = hmac.new(
                    webhook.secret.encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers['X-TrustScan-Signature'] = signature
            
            headers['X-TrustScan-Event'] = event_type
            headers['X-TrustScan-Delivery'] = str(delivery.id)
            
            response = requests.post(
                webhook.url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            delivery.response_code = response.status_code
            delivery.response_body = response.text[:1000]
            
            if 200 <= response.status_code < 300:
                delivery.status = 'delivered'
                delivery.delivered_at = timezone.now()
                delivery.save(update_fields=['status', 'delivered_at', 'response_code', 'response_body'])
                
                webhook.last_triggered_at = timezone.now()
                webhook.failure_count = 0
                webhook.last_failure = ''
                webhook.save(update_fields=['last_triggered_at', 'failure_count', 'last_failure'])
                
                return {'status': 'delivered', 'attempt': attempt}
            
            else:
                delivery.error_message = f'HTTP {response.status_code}: {response.text[:500]}'
        
        except requests.Timeout:
            delivery.error_message = 'Request timeout'
        except requests.ConnectionError:
            delivery.error_message = 'Connection error'
        except Exception as e:
            delivery.error_message = str(e)
        
        delivery.save(update_fields=['error_message'])
        
        if attempt < 5:
            retry_delay = min(60 * (2 ** attempt), 3600)
            delivery.next_retry = timezone.now() + timezone.timedelta(seconds=retry_delay)
            delivery.save(update_fields=['next_retry'])
            raise self.retry(exc=Exception(f"Attempt {attempt} failed"), countdown=retry_delay)
    
    delivery.status = 'failed'
    delivery.save(update_fields=['status'])
    
    webhook.failure_count += 1
    webhook.last_failure = delivery.error_message
    webhook.save(update_fields=['failure_count', 'last_failure'])
    
    logger.error(f"Webhook {webhook_id} failed after 5 attempts: {delivery.error_message}")
    
    return {'status': 'failed', 'attempts': 5}


@shared_task
def send_test_webhook(webhook_id: str):
    from apps.api.models import WebhookEndpoint
    
    try:
        webhook = WebhookEndpoint.objects.get(id=webhook_id)
    except WebhookEndpoint.DoesNotExist:
        return {'status': 'error', 'reason': 'webhook_not_found'}
    
    payload = {
        'test': True,
        'message': 'This is a test webhook from TrustScan',
        'timestamp': timezone.now().isoformat(),
    }
    
    send_webhook.delay(str(webhook_id), 'test', payload)
    
    return {'status': 'queued'}


@shared_task
def log_api_request(api_key_id: str, organization_id: str, method: str, path: str,
                    query_params: dict, request_body: dict, response_status: int,
                    response_body: dict, ip_address: str, user_agent: str, duration_ms: int):
    from apps.api.models import APIRequestLog, APIUsageQuota
    
    APIRequestLog.objects.create(
        api_key_id=api_key_id,
        organization_id=organization_id,
        method=method,
        path=path,
        query_params=query_params,
        request_body=request_body,
        response_status=response_status,
        response_body=response_body,
        ip_address=ip_address,
        user_agent=user_agent,
        duration_ms=duration_ms,
    )
    
    quota, _ = APIUsageQuota.objects.get_or_create(
        organization_id=organization_id,
        period_start=timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0),
        defaults={
            'period_end': (timezone.now().replace(day=1) + timezone.timedelta(days=32)).replace(day=1),
            'requests_limit': 10000,
        }
    )
    
    quota.requests_count += 1
    if path.startswith('/scan'):
        quota.scan_requests += 1
    elif path.startswith('/report'):
        quota.report_requests += 1
    quota.save(update_fields=['requests_count', 'scan_requests', 'report_requests'])
    
    return {'status': 'logged'}


@shared_task
def cleanup_old_api_logs():
    from apps.api.models import APIRequestLog, APIUsageQuota, WebhookDelivery
    from datetime import timedelta
    
    cutoff = timezone.now() - timedelta(days=90)
    
    deleted_logs = APIRequestLog.objects.filter(timestamp__lt=cutoff).delete()
    deleted_deliveries = WebhookDelivery.objects.filter(created_at__lt=cutoff).delete()
    deleted_quotas = APIUsageQuota.objects.filter(period_end__lt=cutoff).delete()
    
    return {
        'logs_deleted': deleted_logs[0],
        'deliveries_deleted': deleted_deliveries[0],
        'quotas_deleted': deleted_quotas[0],
    }