import uuid
from django.db import models
from django.utils import timezone
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import (
    ReportTypeChoices, ReportFormatChoices
)


class TrustReport(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='trust_reports'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='trust_reports'
    )
    trust_score = models.ForeignKey(
        'scoring.TrustScore',
        on_delete=models.CASCADE,
        related_name='trust_reports'
    )
    
    report_type = models.CharField(max_length=30, choices=ReportTypeChoices.choices)
    format = models.CharField(max_length=20, choices=ReportFormatChoices.choices, default='pdf')
    
    title = models.CharField(max_length=255)
    summary = models.TextField(blank=True)
    
    content_html = models.TextField(blank=True)
    content_json = models.JSONField(default=dict)
    content_markdown = models.TextField(blank=True)
    
    file = models.FileField(upload_to='reports/%Y/%m/%d/', null=True, blank=True)
    file_size = models.PositiveIntegerField(default=0)
    file_hash = models.CharField(max_length=64, blank=True)
    
    template_version = models.CharField(max_length=20, default='1.0')
    generation_time_ms = models.PositiveIntegerField(default=0)
    
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('generating', 'Generating'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ], default='pending')
    
    error_message = models.TextField(blank=True)
    
    is_public = models.BooleanField(default=False)
    public_token = models.CharField(max_length=64, blank=True, unique=True, null=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    generated_at = models.DateTimeField(auto_now_add=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    delivery_method = models.CharField(max_length=20, choices=[
        ('email', 'Email'),
        ('webhook', 'Webhook'),
        ('download', 'Direct Download'),
        ('api', 'API'),
    ], blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'reports_trustreport'
        verbose_name = 'Trust Report'
        verbose_name_plural = 'Trust Reports'
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['scan_job', 'report_type']),
            models.Index(fields=['domain', '-generated_at']),
            models.Index(fields=['public_token']),
        ]

    def __str__(self):
        return f"{self.domain} - {self.get_report_type_display()} ({self.format})"


class ReportTemplate(UUIDTimestampedSoftDeleteModel):
    name = models.CharField(max_length=100, unique=True)
    report_type = models.CharField(max_length=30, choices=ReportTypeChoices.choices)
    format = models.CharField(max_length=20, choices=ReportFormatChoices.choices)
    
    version = models.CharField(max_length=20, default='1.0')
    description = models.TextField(blank=True)
    
    template_file = models.FileField(upload_to='templates/reports/', null=True, blank=True)
    template_content = models.TextField(blank=True)
    
    context_variables = models.JSONField(default=dict)
    required_sections = models.JSONField(default=list)
    optional_sections = models.JSONField(default=list)
    
    is_active = models.BooleanField(default=True)
    is_default = models.BooleanField(default=False)
    
    supported_formats = models.JSONField(default=list)
    
    css_styles = models.TextField(blank=True)
    header_html = models.TextField(blank=True)
    footer_html = models.TextField(blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'reports_reporttemplate'
        verbose_name = 'Report Template'
        verbose_name_plural = 'Report Templates'
        unique_together = [['report_type', 'format', 'is_default']]

    def __str__(self):
        return f"{self.name} ({self.report_type} - {self.format})"


class ReportSchedule(UUIDTimestampedSoftDeleteModel):
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='report_schedules'
    )
    name = models.CharField(max_length=100)
    
    report_types = models.JSONField(default=list)
    format = models.CharField(max_length=20, choices=ReportFormatChoices.choices, default='pdf')
    template = models.ForeignKey(
        ReportTemplate,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='schedules'
    )
    
    frequency = models.CharField(max_length=20, choices=[
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
        ('after_scan', 'After Each Scan'),
    ])
    
    day_of_week = models.PositiveSmallIntegerField(null=True, blank=True)
    day_of_month = models.PositiveSmallIntegerField(null=True, blank=True)
    hour = models.PositiveSmallIntegerField(default=9)
    minute = models.PositiveSmallIntegerField(default=0)
    timezone = models.CharField(max_length=50, default='Africa/Nairobi')
    
    recipients = models.JSONField(default=list)
    webhook_url = models.URLField(blank=True)
    webhook_secret = models.CharField(max_length=100, blank=True)
    
    is_active = models.BooleanField(default=True)
    last_run = models.DateTimeField(null=True, blank=True)
    next_run = models.DateTimeField(null=True, blank=True, db_index=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'reports_reportschedule'
        verbose_name = 'Report Schedule'
        verbose_name_plural = 'Report Schedules'

    def __str__(self):
        return f"{self.name} - {self.domain} ({self.frequency})"


class ReportDelivery(UUIDTimestampedSoftDeleteModel):
    report = models.ForeignKey(
        TrustReport,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )
    
    method = models.CharField(max_length=20, choices=[
        ('email', 'Email'),
        ('webhook', 'Webhook'),
        ('api', 'API'),
        ('download', 'Direct Download'),
    ])
    
    recipient = models.CharField(max_length=255)
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('sent', 'Sent'),
        ('delivered', 'Delivered'),
        ('opened', 'Opened'),
        ('failed', 'Failed'),
        ('bounced', 'Bounced'),
    ], default='pending')
    
    sent_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(null=True, blank=True)
    opened_at = models.DateTimeField(null=True, blank=True)
    
    response_code = models.PositiveIntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    retry_count = models.PositiveSmallIntegerField(default=0)
    next_retry = models.DateTimeField(null=True, blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'reports_reportdelivery'
        verbose_name = 'Report Delivery'
        verbose_name_plural = 'Report Deliveries'

    def __str__(self):
        return f"{self.report} -> {self.recipient} ({self.status})"