import re
import uuid
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import (
    VerificationMethodChoices,
    AuthorizationStatusChoices,
    TLDCategoryChoices,
    IndustryChoices,
)


def validate_domain_format(value):
    value = value.lower().strip()
    value = value.replace('http://', '').replace('https://', '').strip('/')
    if value.startswith('www.'):
        value = value[4:]

    domain_pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    if not domain_pattern.match(value):
        raise ValidationError(f'Invalid domain format: {value}')

    return value


class Domain(UUIDTimestampedSoftDeleteModel):
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='domains'
    )
    name = models.CharField(max_length=255, validators=[validate_domain_format], db_index=True)
    root_domain = models.CharField(max_length=255, db_index=True)
    tld = models.CharField(max_length=50)
    tld_category = models.CharField(max_length=20, choices=TLDCategoryChoices.choices)
    
    industry = models.CharField(max_length=30, choices=IndustryChoices.choices, blank=True)
    is_primary = models.BooleanField(default=False)
    
    authorization_status = models.CharField(
        max_length=25,
        choices=AuthorizationStatusChoices.choices,
        default=AuthorizationStatusChoices.UNVERIFIED,
        db_index=True
    )
    verification_method = models.CharField(
        max_length=20,
        choices=VerificationMethodChoices.choices,
        blank=True
    )
    verification_token = models.CharField(max_length=128, blank=True)
    verification_token_hash = models.CharField(max_length=64, blank=True)
    verification_token_expires_at = models.DateTimeField(null=True, blank=True)
    verification_attempts = models.PositiveSmallIntegerField(default=0)
    verified_at = models.DateTimeField(null=True, blank=True)
    authorized_at = models.DateTimeField(null=True, blank=True)
    authorized_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='authorized_domains'
    )
    authorization_scope = models.JSONField(default=list)
    authorization_expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='revoked_domains'
    )
    revocation_reason = models.TextField(blank=True)

    dns_resolves = models.BooleanField(default=None, null=True)
    last_dns_check_at = models.DateTimeField(null=True, blank=True)
    mx_records = models.JSONField(default=list)
    name_servers = models.JSONField(default=list)
    registrar = models.CharField(max_length=255, blank=True)
    registration_date = models.DateTimeField(null=True, blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True)
    privacy_protection = models.BooleanField(default=False)

    current_trust_score = models.PositiveSmallIntegerField(null=True, blank=True)
    current_score_status = models.CharField(max_length=20, blank=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    last_scan_status = models.CharField(max_length=20, blank=True)
    scan_count = models.PositiveIntegerField(default=0)

    is_monitored = models.BooleanField(default=True)
    monitoring_frequency = models.CharField(max_length=20, choices=[
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly'),
        ('quarterly', 'Quarterly'),
    ], default='weekly')
    next_scheduled_scan = models.DateTimeField(null=True, blank=True)
    
    alert_on_score_drop = models.PositiveSmallIntegerField(default=10)
    alert_on_critical = models.BooleanField(default=True)
    alert_on_new_subdomain = models.BooleanField(default=True)
    alert_on_ssl_expiry = models.BooleanField(default=True)
    alert_on_breach = models.BooleanField(default=True)

    notes = models.TextField(blank=True)
    tags = models.JSONField(default=list)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'domains_domain'
        verbose_name = 'Domain'
        verbose_name_plural = 'Domains'
        ordering = ['-created_at']
        unique_together = [['organization', 'name']]
        indexes = [
            models.Index(fields=['organization', 'authorization_status']),
            models.Index(fields=['next_scheduled_scan']),
            models.Index(fields=['root_domain']),
        ]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.root_domain:
            self.root_domain = self.extract_root_domain(self.name)
        if not self.tld:
            self.tld = self.extract_tld(self.name)
        if not self.tld_category:
            self.tld_category = self.determine_tld_category(self.tld)
        super().save(*args, **kwargs)

    @staticmethod
    def extract_root_domain(domain):
        parts = domain.split('.')
        if len(parts) > 2:
            if parts[-2] in ('co', 'com', 'org', 'net', 'edu', 'gov', 'ac', 'mil', 'ke'):
                return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    @staticmethod
    def extract_tld(domain):
        parts = domain.split('.')
        if len(parts) > 2 and parts[-2] in ('co', 'com', 'org', 'net', 'edu', 'gov', 'ac', 'mil', 'ke'):
            return '.'.join(parts[-2:])
        return parts[-1]

    @staticmethod
    def determine_tld_category(tld):
        generic_tlds = {'com', 'org', 'net', 'info', 'biz', 'name', 'pro', 'xyz', 'online', 'site', 'tech', 'store', 'app', 'dev', 'io', 'ai', 'co'}
        sponsored_tlds = {'edu', 'gov', 'mil', 'aero', 'museum', 'coop', 'int', 'jobs', 'mobi', 'travel', 'asia', 'cat', 'tel'}
        country_tlds = {'ke', 'uk', 'us', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in', 'br', 'za', 'ng', 'gh', 'tz', 'ug', 'rw'}
        brand_tlds = {'google', 'apple', 'microsoft', 'amazon', 'facebook', 'bmw', 'audi', 'mercedes'}
        
        tld_lower = tld.lower()
        if tld_lower in brand_tlds:
            return TLDCategoryChoices.BRAND
        if tld_lower in generic_tlds:
            return TLDCategoryChoices.GENERIC
        if tld_lower in sponsored_tlds:
            return TLDCategoryChoices.SPONSORED
        if tld_lower in country_tlds:
            return TLDCategoryChoices.COUNTRY_CODE
        if len(tld_lower) > 3:
            return TLDCategoryChoices.NEW_GTLD
        return TLDCategoryChoices.COUNTRY_CODE

    def can_scan(self):
        return self.authorization_status == AuthorizationStatusChoices.AUTHORIZED

    def is_authorization_expiring(self, days=30):
        if not self.authorization_expires_at:
            return False
        return self.authorization_expires_at <= timezone.now() + timezone.timedelta(days=days)


class DomainVerificationLog(UUIDTimestampedSoftDeleteModel):
    domain = models.ForeignKey(
        Domain,
        on_delete=models.CASCADE,
        related_name='verification_logs'
    )
    method = models.CharField(max_length=20, choices=VerificationMethodChoices.choices)
    token = models.CharField(max_length=128)
    token_hash = models.CharField(max_length=64)
    status = models.CharField(max_length=20, choices=[
        ('initiated', 'Initiated'),
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('failed', 'Failed'),
        ('expired', 'Expired'),
    ])
    resolver_used = models.CharField(max_length=50, blank=True)
    checked_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)
    error_message = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'domains_verificationlog'
        verbose_name = 'Domain Verification Log'
        verbose_name_plural = 'Domain Verification Logs'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.domain} - {self.method} - {self.status}"


class DomainPortfolio(UUIDTimestampedSoftDeleteModel):
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='portfolios'
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    domains = models.ManyToManyField(Domain, related_name='portfolios', blank=True)
    is_default = models.BooleanField(default=False)
    settings = models.JSONField(default=dict)

    class Meta:
        db_table = 'domains_portfolio'
        verbose_name = 'Domain Portfolio'
        verbose_name_plural = 'Domain Portfolios'
        unique_together = [['organization', 'name']]

    def __str__(self):
        return f"{self.organization.name} - {self.name}"


class BlockedDomain(UUIDTimestampedSoftDeleteModel):
    domain = models.CharField(max_length=255, db_index=True)
    reason = models.TextField()
    blocked_by = models.ForeignKey(
        'accounts.User',
        on_delete=models.SET_NULL,
        null=True,
        related_name='blocked_domains'
    )
    is_regex = models.BooleanField(default=False)
    expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'domains_blocked'
        verbose_name = 'Blocked Domain'
        verbose_name_plural = 'Blocked Domains'
        ordering = ['-created_at']

    def __str__(self):
        return self.domain