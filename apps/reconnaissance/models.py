import uuid
from django.db import models
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import (
    SeverityChoices, SignalTypeChoices, AssetTypeChoices,
    SourceLayerChoices, SignalCategoryChoices, DimensionChoices,
    RemediationPriorityChoices
)


class Finding(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='findings'
    )
    asset = models.ForeignKey(
        'discovery.Asset',
        on_delete=models.CASCADE,
        related_name='findings'
    )
    
    source_layer = models.CharField(
        max_length=30,
        choices=SourceLayerChoices.choices,
        db_index=True
    )
    source_provider = models.CharField(max_length=100)
    
    asset_type = models.CharField(
        max_length=20,
        choices=AssetTypeChoices.choices
    )
    asset_value = models.TextField()
    
    signal_type = models.CharField(
        max_length=20,
        choices=SignalTypeChoices.choices
    )
    signal_category = models.CharField(
        max_length=30,
        choices=SignalCategoryChoices.choices
    )
    dimension = models.CharField(
        max_length=25,
        choices=DimensionChoices.choices
    )
    
    severity = models.CharField(
        max_length=10,
        choices=SeverityChoices.choices,
        db_index=True
    )
    confidence = models.PositiveSmallIntegerField(default=0)
    
    title = models.CharField(max_length=255)
    description = models.TextField()
    finding_summary = models.TextField()
    
    raw_data = models.JSONField(default=dict)
    normalized_data = models.JSONField(default=dict)
    technical_details = models.JSONField(default=dict)
    
    impact_score = models.SmallIntegerField(default=0)
    cvss_score = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    cve_ids = models.JSONField(default=list)
    
    remediation_action = models.TextField(blank=True)
    remediation_priority = models.PositiveSmallIntegerField(
        choices=RemediationPriorityChoices.choices,
        default=RemediationPriorityChoices.MEDIUM
    )
    remediation_effort = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ], default='medium')
    references = models.JSONField(default=list)
    
    first_seen_at = models.DateTimeField(auto_now_add=True, db_index=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    is_acknowledged = models.BooleanField(default=False)
    is_false_positive = models.BooleanField(default=False)
    false_positive_reason = models.TextField(blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'reconnaissance_finding'
        verbose_name = 'Finding'
        verbose_name_plural = 'Findings'
        ordering = ['-severity', '-created_at']
        indexes = [
            models.Index(fields=['scan_job', 'severity']),
            models.Index(fields=['source_layer', 'dimension']),
            models.Index(fields=['signal_category']),
            models.Index(fields=['is_false_positive']),
        ]

    def __str__(self):
        return f"{self.title} ({self.severity})"


class InspectorResult(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='inspector_results'
    )
    inspector_name = models.CharField(max_length=100)
    inspector_type = models.CharField(max_length=50, choices=[
        ('dns', 'DNS Inspector'),
        ('ssl', 'SSL/TLS Inspector'),
        ('email', 'Email Security Inspector'),
        ('web', 'Web Security Inspector'),
        ('tech', 'Technology Profiler'),
        ('exposure', 'Exposure Detector'),
        ('reputation', 'Reputation Monitor'),
        ('breach', 'Breach Intelligence'),
        ('cloud', 'Cloud Intelligence'),
        ('github', 'GitHub Intelligence'),
        ('api', 'API Intelligence'),
    ])
    
    status = models.CharField(max_length=20, choices=[
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('skipped', 'Skipped'),
    ], default='pending')
    
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    duration_ms = models.PositiveIntegerField(default=0)
    
    assets_scanned = models.PositiveIntegerField(default=0)
    findings_generated = models.PositiveIntegerField(default=0)
    critical_findings = models.PositiveIntegerField(default=0)
    high_findings = models.PositiveIntegerField(default=0)
    medium_findings = models.PositiveIntegerField(default=0)
    low_findings = models.PositiveIntegerField(default=0)
    info_findings = models.PositiveIntegerField(default=0)
    
    error_message = models.TextField(blank=True)
    error_details = models.JSONField(default=dict)
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'reconnaissance_inspectorresult'
        verbose_name = 'Inspector Result'
        verbose_name_plural = 'Inspector Results'
        ordering = ['-created_at']
        unique_together = [['scan_job', 'inspector_name']]

    def __str__(self):
        return f"{self.inspector_name} - {self.status}"


class TechnologyFingerprint(UUIDTimestampedSoftDeleteModel):
    asset = models.ForeignKey(
        'discovery.Asset',
        on_delete=models.CASCADE,
        related_name='technology_fingerprints'
    )
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='technology_fingerprints'
    )
    
    category = models.CharField(max_length=50, choices=[
        ('server', 'Web Server'),
        ('framework', 'Framework'),
        ('cms', 'CMS'),
        ('language', 'Programming Language'),
        ('database', 'Database'),
        ('cdn', 'CDN'),
        ('analytics', 'Analytics'),
        ('javascript', 'JavaScript Library'),
        ('css', 'CSS Framework'),
        ('security', 'Security'),
        ('other', 'Other'),
    ])
    
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=50, blank=True)
    confidence = models.PositiveSmallIntegerField(default=0)
    
    detection_method = models.CharField(max_length=50, choices=[
        ('header', 'HTTP Header'),
        ('html', 'HTML Content'),
        ('script', 'JavaScript'),
        ('cookie', 'Cookie'),
        ('meta', 'Meta Tag'),
        ('path', 'Path/URL'),
        ('error', 'Error Page'),
        ('certificate', 'SSL Certificate'),
    ])
    
    evidence = models.JSONField(default=dict)
    cpe = models.CharField(max_length=100, blank=True)

    class Meta:
        db_table = 'reconnaissance_technologyfingerprint'
        verbose_name = 'Technology Fingerprint'
        verbose_name_plural = 'Technology Fingerprints'
        ordering = ['-confidence', 'category', 'name']
        unique_together = [['scan_job', 'asset', 'category', 'name', 'version']]

    def __str__(self):
        return f"{self.name} {self.version} ({self.category})"


class HTTPResponse(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='http_responses'
    )
    asset = models.ForeignKey(
        'discovery.Asset',
        on_delete=models.CASCADE,
        related_name='http_responses'
    )
    
    url = models.URLField()
    method = models.CharField(max_length=10, default='GET')
    status_code = models.PositiveSmallIntegerField()
    response_time_ms = models.PositiveIntegerField()
    
    request_headers = models.JSONField(default=dict)
    response_headers = models.JSONField(default=dict)
    
    response_body_hash = models.CharField(max_length=64, blank=True)
    response_body_size = models.PositiveIntegerField(default=0)
    
    redirect_chain = models.JSONField(default=list)
    final_url = models.URLField(blank=True)
    
    ssl_info = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    port = models.PositiveSmallIntegerField(default=443)
    
    error = models.TextField(blank=True)

    class Meta:
        db_table = 'reconnaissance_httpresponse'
        verbose_name = 'HTTP Response'
        verbose_name_plural = 'HTTP Responses'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.method} {self.url} -> {self.status_code}"


class SecurityHeaderFinding(UUIDTimestampedSoftDeleteModel):
    http_response = models.ForeignKey(
        HTTPResponse,
        on_delete=models.CASCADE,
        related_name='security_header_findings'
    )
    
    header_name = models.CharField(max_length=100)
    header_value = models.TextField(blank=True)
    is_present = models.BooleanField(default=False)
    is_secure = models.BooleanField(default=False)
    
    severity = models.CharField(max_length=10, choices=SeverityChoices.choices)
    recommendation = models.TextField(blank=True)

    class Meta:
        db_table = 'reconnaissance_securityheaderfinding'
        verbose_name = 'Security Header Finding'
        verbose_name_plural = 'Security Header Findings'

    def __str__(self):
        return f"{self.header_name} - {'Present' if self.is_present else 'Missing'}"


class SSLConfiguration(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='ssl_configurations'
    )
    asset = models.ForeignKey(
        'discovery.Asset',
        on_delete=models.CASCADE,
        related_name='ssl_configurations'
    )
    
    hostname = models.CharField(max_length=255)
    port = models.PositiveSmallIntegerField(default=443)
    ip_address = models.GenericIPAddressField()
    
    protocol_version = models.CharField(max_length=20)
    cipher_suite = models.CharField(max_length=100)
    key_exchange = models.CharField(max_length=50)
    
    certificate = models.JSONField(default=dict)
    certificate_chain = models.JSONField(default=list)
    
    supports_tls10 = models.BooleanField(default=False)
    supports_tls11 = models.BooleanField(default=False)
    supports_tls12 = models.BooleanField(default=True)
    supports_tls13 = models.BooleanField(default=False)
    
    hsts_enabled = models.BooleanField(default=False)
    hsts_max_age = models.PositiveIntegerField(null=True, blank=True)
    hsts_preload = models.BooleanField(default=False)
    hsts_include_subdomains = models.BooleanField(default=False)
    
    ocsp_stapling = models.BooleanField(default=False)
    cert_transparency = models.BooleanField(default=False)
    
    vulnerabilities = models.JSONField(default=list)
    grade = models.CharField(max_length=2, blank=True)
    score = models.PositiveSmallIntegerField(default=0)

    class Meta:
        db_table = 'reconnaissance_sslconfiguration'
        verbose_name = 'SSL Configuration'
        verbose_name_plural = 'SSL Configurations'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.hostname}:{self.port} - {self.grade}"


class EmailSecurityRecord(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='email_security_records'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='email_security_records'
    )
    
    spf_record = models.TextField(blank=True)
    spf_version = models.CharField(max_length=10, blank=True)
    spf_mechanisms = models.JSONField(default=list)
    spf_qualifier = models.CharField(max_length=10, blank=True)
    spf_policy = models.CharField(max_length=20, blank=True)
    spf_all_mechanism = models.CharField(max_length=10, blank=True)
    
    dkim_selectors = models.JSONField(default=list)
    dkim_records = models.JSONField(default=dict)
    
    dmarc_record = models.TextField(blank=True)
    dmarc_version = models.CharField(max_length=10, blank=True)
    dmarc_policy = models.CharField(max_length=20, blank=True)
    dmarc_subdomain_policy = models.CharField(max_length=20, blank=True)
    dmarc_percentage = models.PositiveSmallIntegerField(null=True, blank=True)
    dmarc_rua = models.TextField(blank=True)
    dmarc_ruf = models.TextField(blank=True)
    
    bimi_record = models.TextField(blank=True)
    bimi_logo_url = models.URLField(blank=True)
    
    mx_records = models.JSONField(default=list)
    mx_provider = models.CharField(max_length=100, blank=True)
    
    is_valid = models.BooleanField(default=False)
    validation_errors = models.JSONField(default=list)

    class Meta:
        db_table = 'reconnaissance_emailsecurityrecord'
        verbose_name = 'Email Security Record'
        verbose_name_plural = 'Email Security Records'
        unique_together = [['scan_job', 'domain']]

    def __str__(self):
        return f"Email Security for {self.domain}"


class BreachRecord(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='breach_records'
    )
    
    email = models.EmailField(db_index=True)
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='breach_records'
    )
    
    breach_name = models.CharField(max_length=255)
    breach_date = models.DateTimeField()
    breach_added_date = models.DateTimeField()
    
    data_classes = models.JSONField(default=list)
    is_verified = models.BooleanField(default=True)
    is_fabricated = models.BooleanField(default=False)
    is_sensitive = models.BooleanField(default=False)
    is_retired = models.BooleanField(default=False)
    is_spam_list = models.BooleanField(default=False)
    is_malware = models.BooleanField(default=False)
    is_subscription_free = models.BooleanField(default=True)
    
    pwn_count = models.PositiveIntegerField(default=0)
    description = models.TextField(blank=True)
    logo_path = models.CharField(max_length=255, blank=True)
    
    password_exposure = models.CharField(max_length=20, choices=[
        ('plaintext', 'Plaintext'),
        ('hashed', 'Hashed'),
        ('unknown', 'Unknown'),
        ('none', 'None'),
    ], default='unknown')
    
    source = models.CharField(max_length=50, default='haveibeenpwned')

    class Meta:
        db_table = 'reconnaissance_breachrecord'
        verbose_name = 'Breach Record'
        verbose_name_plural = 'Breach Records'
        ordering = ['-breach_date']
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['domain', 'breach_date']),
        ]

    def __str__(self):
        return f"{self.email} - {self.breach_name}"


class ExposedService(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='exposed_services'
    )
    asset = models.ForeignKey(
        'discovery.Asset',
        on_delete=models.CASCADE,
        related_name='exposed_services'
    )
    
    ip_address = models.GenericIPAddressField()
    port = models.PositiveSmallIntegerField()
    protocol = models.CharField(max_length=10, default='tcp')
    
    service_name = models.CharField(max_length=100)
    service_version = models.CharField(max_length=100, blank=True)
    service_product = models.CharField(max_length=100, blank=True)
    
    banner = models.TextField(blank=True)
    
    transport = models.CharField(max_length=10, choices=[
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
    ], default='tcp')
    
    state = models.CharField(max_length=20, default='open')
    reason = models.CharField(max_length=50, blank=True)
    
    shodan_id = models.CharField(max_length=100, blank=True)
    shodan_hostnames = models.JSONField(default=list)
    shodan_org = models.CharField(max_length=255, blank=True)
    shodan_isp = models.CharField(max_length=255, blank=True)
    shodan_asn = models.CharField(max_length=50, blank=True)
    shodan_country = models.CharField(max_length=2, blank=True)
    
    cpe = models.JSONField(default=list)
    vulnerabilities = models.JSONField(default=list)
    
    source = models.CharField(max_length=50, default='shodan')
    confidence = models.PositiveSmallIntegerField(default=70)

    class Meta:
        db_table = 'reconnaissance_exposedservice'
        verbose_name = 'Exposed Service'
        verbose_name_plural = 'Exposed Services'
        ordering = ['ip_address', 'port']
        unique_together = [['scan_job', 'ip_address', 'port', 'protocol']]

    def __str__(self):
        return f"{self.ip_address}:{self.port} ({self.service_name})"


class ReputationFinding(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='reputation_findings'
    )
    asset = models.ForeignKey(
        'discovery.Asset',
        on_delete=models.CASCADE,
        related_name='reputation_findings'
    )
    
    source = models.CharField(max_length=50)
    category = models.CharField(max_length=50, choices=[
        ('malware', 'Malware'),
        ('phishing', 'Phishing'),
        ('spam', 'Spam'),
        ('botnet', 'Botnet'),
        ('exploit', 'Exploit'),
        ('suspicious', 'Suspicious'),
        ('clean', 'Clean'),
    ])
    
    is_listed = models.BooleanField(default=False)
    listing_details = models.JSONField(default=dict)
    confidence = models.PositiveSmallIntegerField(default=0)
    
    detection_date = models.DateTimeField(null=True, blank=True)
    last_check = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'reconnaissance_reputationfinding'
        verbose_name = 'Reputation Finding'
        verbose_name_plural = 'Reputation Findings'
        unique_together = [['scan_job', 'asset', 'source']]

    def __str__(self):
        status = "LISTED" if self.is_listed else "CLEAN"
        return f"{self.asset} - {self.source} - {status}"


class GitHubRepository(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='github_repositories'
    )
    domain = models.ForeignKey(
        'domains.Domain',
        on_delete=models.CASCADE,
        related_name='github_repositories'
    )
    
    repo_id = models.BigIntegerField()
    full_name = models.CharField(max_length=255)
    html_url = models.URLField()
    description = models.TextField(blank=True)
    
    is_private = models.BooleanField(default=False)
    is_fork = models.BooleanField(default=False)
    is_archived = models.BooleanField(default=False)
    is_disabled = models.BooleanField(default=False)
    
    language = models.CharField(max_length=50, blank=True)
    languages = models.JSONField(default=dict)
    topics = models.JSONField(default=list)
    
    stars = models.PositiveIntegerField(default=0)
    watchers = models.PositiveIntegerField(default=0)
    forks = models.PositiveIntegerField(default=0)
    open_issues = models.PositiveIntegerField(default=0)
    
    default_branch = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField()
    updated_at = models.DateTimeField()
    pushed_at = models.DateTimeField()
    
    license_name = models.CharField(max_length=100, blank=True)
    license_url = models.URLField(blank=True)
    
    secrets_found = models.PositiveIntegerField(default=0)
    secrets_details = models.JSONField(default=list)
    
    workflows = models.JSONField(default=list)
    dependabot_alerts = models.PositiveIntegerField(default=0)

    class Meta:
        db_table = 'reconnaissance_githubrepository'
        verbose_name = 'GitHub Repository'
        verbose_name_plural = 'GitHub Repositories'
        unique_together = [['scan_job', 'repo_id']]

    def __str__(self):
        return self.full_name


class APIEndpoint(UUIDTimestampedSoftDeleteModel):
    scan_job = models.ForeignKey(
        'scanner.ScanJob',
        on_delete=models.CASCADE,
        related_name='api_endpoints'
    )
    asset = models.ForeignKey(
        'discovery.Asset',
        on_delete=models.CASCADE,
        related_name='api_endpoints'
    )
    
    url = models.URLField()
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    
    api_type = models.CharField(max_length=30, choices=[
        ('rest', 'REST'),
        ('graphql', 'GraphQL'),
        ('grpc', 'gRPC'),
        ('soap', 'SOAP'),
        ('websocket', 'WebSocket'),
        ('other', 'Other'),
    ])
    
    has_auth = models.BooleanField(default=False)
    auth_type = models.CharField(max_length=50, blank=True)
    requires_api_key = models.BooleanField(default=False)
    requires_oauth = models.BooleanField(default=False)
    requires_basic_auth = models.BooleanField(default=False)
    
    spec_url = models.URLField(blank=True)
    spec_type = models.CharField(max_length=20, blank=True)
    
    parameters = models.JSONField(default=list)
    responses = models.JSONField(default=dict)
    
    is_documented = models.BooleanField(default=False)
    documentation_url = models.URLField(blank=True)
    
    risk_level = models.CharField(max_length=10, choices=SeverityChoices.choices, default=SeverityChoices.INFO)
    sensitive_data_exposed = models.BooleanField(default=False)

    class Meta:
        db_table = 'reconnaissance_apiendpoint'
        verbose_name = 'API Endpoint'
        verbose_name_plural = 'API Endpoints'
        unique_together = [['scan_job', 'url', 'method']]

    def __str__(self):
        return f"{self.method} {self.path}"