import uuid
from django.db import models
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import AssetTypeChoices


class Asset(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='assets'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='discovered_assets'
    )
    
    asset_type = models.CharField(
        max_length=30,
        choices=AssetTypeChoices.choices,
        db_index=True
    )
    value = models.CharField(max_length=500, db_index=True)
    name = models.CharField(max_length=255, blank=True)
    
    parent_asset = models.ForeignKey(
        'self',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='child_assets'
    )
    
    source = models.CharField(max_length=50, choices=[
        ('dns', 'DNS Resolution'),
        ('certificate', 'Certificate Transparency'),
        ('passive_dns', 'Passive DNS'),
        ('bruteforce', 'Dictionary Enumeration'),
        ('manual', 'Manual Entry'),
        ('reconnaissance', 'Reconnaissance'),
    ], default='dns')
    
    is_active = models.BooleanField(default=True, db_index=True)
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    scan_count = models.PositiveIntegerField(default=1)
    
    metadata = models.JSONField(default=dict)
    tags = models.JSONField(default=list)
    risk_score = models.PositiveSmallIntegerField(default=0, db_index=True)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    ip_version = models.PositiveSmallIntegerField(null=True, blank=True)
    asn = models.PositiveIntegerField(null=True, blank=True)
    asn_name = models.CharField(max_length=255, blank=True)
    geo_country = models.CharField(max_length=2, blank=True)
    geo_region = models.CharField(max_length=100, blank=True)
    geo_city = models.CharField(max_length=100, blank=True)
    cdn_provider = models.CharField(max_length=100, blank=True)
    cloud_provider = models.CharField(max_length=100, blank=True)

    class Meta:
        db_table = 'discovery_asset'
        verbose_name = 'Asset'
        verbose_name_plural = 'Assets'
        unique_together = [['scan_job', 'asset_type', 'value']]
        indexes = [
            models.Index(fields=['scan_job', 'asset_type']),
            models.Index(fields=['domain', 'is_active']),
            models.Index(fields=['asset_type', 'is_active']),
            models.Index(fields=['risk_score']),
        ]

    def __str__(self):
        return f"{self.asset_type}: {self.value}"


class DiscoveryMap(UUIDTimestampedSoftDeleteModel):
    scan_job = models.OneToOneField(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='discovery_map_obj'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='discovery_maps'
    )
    
    root_domain = models.CharField(max_length=253)
    tld = models.CharField(max_length=50)
    
    registration = models.JSONField(default=dict)
    dns_records = models.JSONField(default=dict)
    
    discovered_subdomains = models.JSONField(default=list)
    certificate_log_entries = models.JSONField(default=list)
    ip_addresses = models.JSONField(default=list)
    passive_dns_history = models.JSONField(default=list)
    
    total_subdomains = models.PositiveIntegerField(default=0)
    total_ips = models.PositiveIntegerField(default=0)
    total_certificates = models.PositiveIntegerField(default=0)
    
    discovery_duration_ms = models.PositiveIntegerField(default=0)
    sources_used = models.JSONField(default=list)
    errors = models.JSONField(default=list)
    
    is_complete = models.BooleanField(default=False)

    class Meta:
        db_table = 'discovery_map'
        verbose_name = 'Discovery Map'
        verbose_name_plural = 'Discovery Maps'

    def __str__(self):
        return f"Discovery Map for {self.root_domain}"


class CertificateEntry(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='certificate_entries'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='certificate_entries'
    )
    
    subdomain = models.CharField(max_length=253, db_index=True)
    all_domains = models.JSONField(default=list)
    
    issuer = models.CharField(max_length=255)
    issuer_ca_id = models.PositiveIntegerField(default=0)
    
    not_before = models.DateTimeField(null=True, blank=True, db_index=True)
    not_after = models.DateTimeField(null=True, blank=True, db_index=True)
    serial_number = models.CharField(max_length=100, blank=True)
    
    signature_algorithm = models.CharField(max_length=100, blank=True)
    public_key_algorithm = models.CharField(max_length=100, blank=True)
    public_key_size = models.PositiveIntegerField(default=0)
    
    source = models.CharField(max_length=20, choices=[
        ('crt.sh', 'crt.sh'),
        ('certspotter', 'CertSpotter'),
        ('manual', 'Manual'),
    ], default='crt.sh')
    
    is_valid = models.BooleanField(default=True)
    is_self_signed = models.BooleanField(default=False)
    is_wildcard = models.BooleanField(default=False)
    is_expiring_soon = models.BooleanField(default=False)
    days_until_expiry = models.PositiveIntegerField(null=True, blank=True)
    
    chain_valid = models.BooleanField(null=True, blank=True)
    chain_length = models.PositiveSmallIntegerField(default=0)
    ocsp_stapling = models.BooleanField(default=False)
    ct_logs = models.JSONField(default=list)

    class Meta:
        db_table = 'discovery_certificateentry'
        verbose_name = 'Certificate Entry'
        verbose_name_plural = 'Certificate Entries'
        indexes = [
            models.Index(fields=['scan_job', 'subdomain']),
            models.Index(fields=['domain', 'not_after']),
            models.Index(fields=['is_expiring_soon']),
            models.Index(fields=['is_self_signed']),
        ]

    def __str__(self):
        return f"Certificate for {self.subdomain}"


class DNSRecord(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='dns_records'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='dns_records'
    )
    
    record_type = models.CharField(max_length=10, db_index=True)
    name = models.CharField(max_length=253, db_index=True)
    value = models.TextField()
    ttl = models.PositiveIntegerField(default=0)
    priority = models.PositiveIntegerField(null=True, blank=True)
    
    source = models.CharField(max_length=20, default='dns')
    is_verified = models.BooleanField(default=False)

    class Meta:
        db_table = 'discovery_dnsrecord'
        verbose_name = 'DNS Record'
        verbose_name_plural = 'DNS Records'
        unique_together = [['scan_job', 'record_type', 'name', 'value']]
        indexes = [
            models.Index(fields=['scan_job', 'record_type']),
            models.Index(fields=['domain', 'record_type']),
        ]

    def __str__(self):
        return f"{self.record_type} {self.name} -> {self.value[:50]}"


class WhoisRecord(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='whois_records'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='whois_records'
    )
    
    registrar = models.CharField(max_length=255, blank=True)
    registrar_iana_id = models.CharField(max_length=50, blank=True)
    registrar_url = models.URLField(blank=True)
    
    registrant_name = models.CharField(max_length=255, blank=True)
    registrant_organization = models.CharField(max_length=255, blank=True)
    registrant_email = models.EmailField(blank=True)
    registrant_phone = models.CharField(max_length=50, blank=True)
    registrant_country = models.CharField(max_length=2, blank=True)
    registrant_state = models.CharField(max_length=100, blank=True)
    registrant_city = models.CharField(max_length=100, blank=True)
    
    admin_contact = models.JSONField(default=dict)
    tech_contact = models.JSONField(default=dict)
    billing_contact = models.JSONField(default=dict)
    
    name_servers = models.JSONField(default=list)
    status = models.JSONField(default=list)
    
    creation_date = models.DateTimeField(null=True, blank=True)
    expiry_date = models.DateTimeField(null=True, blank=True, db_index=True)
    updated_date = models.DateTimeField(null=True, blank=True)
    
    dnssec = models.BooleanField(default=False)
    privacy_protection = models.BooleanField(default=False)
    
    raw_whois = models.TextField(blank=True)

    class Meta:
        db_table = 'discovery_whoisrecord'
        verbose_name = 'WHOIS Record'
        verbose_name_plural = 'WHOIS Records'

    def __str__(self):
        return f"WHOIS for {self.domain}"