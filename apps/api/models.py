import uuid
from django.db import models
from django.utils import timezone
from apps.core.models import UUIDTimestampedSoftDeleteModel


class PublicAPIKey(UUIDTimestampedSoftDeleteModel):
    name = models.CharField(max_length=100)
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='public_api_keys'
    )
    created_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_public_api_keys'
    )
    
    key_prefix = models.CharField(max_length=12, unique=True)
    key_hash = models.CharField(max_length=64)
    
    scopes = models.JSONField(default=list)
    rate_limit = models.PositiveIntegerField(default=1000)
    rate_limit_window = models.PositiveIntegerField(default=3600)
    
    last_used_at = models.DateTimeField(null=True, blank=True)
    last_used_ip = models.GenericIPAddressField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    is_active = models.BooleanField(default=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'api_public_apikey'
        verbose_name = 'Public API Key'
        verbose_name_plural = 'Public API Keys'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'is_active']),
            models.Index(fields=['key_prefix']),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_prefix}...)"


class WebhookEndpoint(UUIDTimestampedSoftDeleteModel):
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='webhook_endpoints'
    )
    
    name = models.CharField(max_length=100)
    url = models.URLField()
    secret = models.CharField(max_length=64)
    
    events = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    failure_count = models.PositiveIntegerField(default=0)
    last_failure = models.TextField(blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'api_webhookendpoint'
        verbose_name = 'Webhook Endpoint'
        verbose_name_plural = 'Webhook Endpoints'

    def __str__(self):
        return f"{self.name} -> {self.url}"


class WebhookDelivery(UUIDTimestampedSoftDeleteModel):
    webhook = models.ForeignKey(
        WebhookEndpoint,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )
    
    event_type = models.CharField(max_length=100)
    payload = models.JSONField()
    
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('delivered', 'Delivered'),
        ('failed', 'Failed'),
    ], default='pending')
    
    response_code = models.PositiveIntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    attempts = models.PositiveIntegerField(default=0)
    next_retry = models.DateTimeField(null=True, blank=True)
    
    delivered_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'api_webhookdelivery'
        verbose_name = 'Webhook Delivery'
        verbose_name_plural = 'Webhook Deliveries'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.webhook} - {self.event_type} ({self.status})"


class APIRequestLog(UUIDTimestampedSoftDeleteModel):
    public_api_key = models.ForeignKey(
        PublicAPIKey,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='request_logs'
    )
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='api_request_logs'
    )
    
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    query_params = models.JSONField(default=dict)
    request_body = models.JSONField(default=dict)
    
    response_status = models.PositiveIntegerField()
    response_body = models.JSONField(default=dict)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    duration_ms = models.PositiveIntegerField(default=0)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = 'api_requestlog'
        verbose_name = 'API Request Log'
        verbose_name_plural = 'API Request Logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization', 'timestamp']),
            models.Index(fields=['public_api_key', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.method} {self.path} -> {self.response_status}"


class APIUsageQuota(UUIDTimestampedSoftDeleteModel):
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='api_usage_quotas'
    )
    
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    
    requests_count = models.PositiveIntegerField(default=0)
    requests_limit = models.PositiveIntegerField(default=10000)
    
    scan_requests = models.PositiveIntegerField(default=0)
    scan_limit = models.PositiveIntegerField(default=100)
    
    report_requests = models.PositiveIntegerField(default=0)
    report_limit = models.PositiveIntegerField(default=100)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'api_usagequota'
        verbose_name = 'API Usage Quota'
        verbose_name_plural = 'API Usage Quotas'
        unique_together = [['organization', 'period_start']]

    def __str__(self):
        return f"{self.organization} - {self.requests_count}/{self.requests_limit}"