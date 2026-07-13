"""
Core app constants and enumerations for TrustScan.
"""

from django.utils.translation import gettext_lazy as _


class ScanStatus:
    PENDING = 'pending'
    AUTHORIZING = 'authorizing'
    AUTHORIZED = 'authorized'
    DISCOVERING = 'discovering'
    RECONNAISSING = 'reconnaissing'
    CORRELATING = 'correlating'
    SCORING = 'scoring'
    INTELLIGENCING = 'intelligencing'
    REPORTING = 'reporting'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'
    TIMEOUT = 'timeout'
    SUSPENDED = 'suspended'

    CHOICES = [
        (PENDING, _('Pending')),
        (AUTHORIZING, _('Authorizing')),
        (AUTHORIZED, _('Authorized')),
        (DISCOVERING, _('Discovering')),
        (RECONNAISSING, _('Reconnaissing')),
        (CORRELATING, _('Correlating')),
        (SCORING, _('Scoring')),
        (INTELLIGENCING, _('Intelligencing')),
        (REPORTING, _('Reporting')),
        (COMPLETED, _('Completed')),
        (FAILED, _('Failed')),
        (CANCELLED, _('Cancelled')),
        (TIMEOUT, _('Timeout')),
        (SUSPENDED, _('Suspended')),
    ]

    TERMINAL_STATES = [COMPLETED, FAILED, CANCELLED, TIMEOUT]
    ACTIVE_STATES = [
        AUTHORIZING, AUTHORIZED, DISCOVERING, RECONNAISSING,
        CORRELATING, SCORING, INTELLIGENCING, REPORTING, SUSPENDED
    ]


class AuthorizationStatus:
    UNVERIFIED = 'unverified'
    PENDING_VERIFICATION = 'pending_verification'
    VERIFIED = 'verified'
    AUTHORIZED = 'authorized'
    SUSPENDED = 'suspended'
    REVOKED = 'revoked'
    EXPIRED = 'expired'

    CHOICES = [
        (UNVERIFIED, _('Unverified')),
        (PENDING_VERIFICATION, _('Pending Verification')),
        (VERIFIED, _('Verified')),
        (AUTHORIZED, _('Authorized')),
        (SUSPENDED, _('Suspended')),
        (REVOKED, _('Revoked')),
        (EXPIRED, _('Expired')),
    ]

    SCANNABLE_STATES = [AUTHORIZED]


class VerificationMethod:
    DNS_TXT = 'dns_txt'
    HTML_FILE = 'html_file'
    META_TAG = 'meta_tag'
    EMAIL = 'email'

    CHOICES = [
        (DNS_TXT, _('DNS TXT Record')),
        (HTML_FILE, _('HTML File Upload')),
        (META_TAG, _('Meta Tag')),
        (EMAIL, _('Email Verification')),
    ]


class Severity:
    INFO = 'info'
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

    CHOICES = [
        (INFO, _('Info')),
        (LOW, _('Low')),
        (MEDIUM, _('Medium')),
        (HIGH, _('High')),
        (CRITICAL, _('Critical')),
    ]

    WEIGHTS = {
        INFO: 1,
        LOW: 2,
        MEDIUM: 5,
        HIGH: 10,
        CRITICAL: 20,
    }

    ORDER = [INFO, LOW, MEDIUM, HIGH, CRITICAL]


class SignalType:
    PRESENCE = 'presence'
    ABSENCE = 'absence'
    MISCONFIGURATION = 'misconfiguration'
    EXPIRATION = 'expiration'
    EXPOSURE = 'exposure'
    BREACH = 'breach'
    REPUTATION = 'reputation'
    VULNERABILITY = 'vulnerability'

    CHOICES = [
        (PRESENCE, _('Presence')),
        (ABSENCE, _('Absence')),
        (MISCONFIGURATION, _('Misconfiguration')),
        (EXPIRATION, _('Expiration')),
        (EXPOSURE, _('Exposure')),
        (BREACH, _('Breach')),
        (REPUTATION, _('Reputation')),
        (VULNERABILITY, _('Vulnerability')),
    ]


class AssetType:
    DOMAIN = 'domain'
    SUBDOMAIN = 'subdomain'
    IP_ADDRESS = 'ip_address'
    EMAIL = 'email'
    CERTIFICATE = 'certificate'
    API_ENDPOINT = 'api_endpoint'
    REPOSITORY = 'repository'
    PORT_SERVICE = 'port_service'
    CLOUD_RESOURCE = 'cloud_resource'

    CHOICES = [
        (DOMAIN, _('Domain')),
        (SUBDOMAIN, _('Subdomain')),
        (IP_ADDRESS, _('IP Address')),
        (EMAIL, _('Email')),
        (CERTIFICATE, _('Certificate')),
        (API_ENDPOINT, _('API Endpoint')),
        (REPOSITORY, _('Repository')),
        (PORT_SERVICE, _('Port Service')),
        (CLOUD_RESOURCE, _('Cloud Resource')),
    ]


class SourceLayer:
    DNS_INTELLIGENCE = 'dns_intelligence'
    CERTIFICATE_INTELLIGENCE = 'certificate_intelligence'
    DOMAIN_INTELLIGENCE = 'domain_intelligence'
    ASSET_DISCOVERY = 'asset_discovery'
    TECHNOLOGY_DETECTION = 'technology_detection'
    EMAIL_SECURITY = 'email_security'
    HTTP_SECURITY = 'http_security'
    REPUTATION_INTELLIGENCE = 'reputation_intelligence'
    BREACH_INTELLIGENCE = 'breach_intelligence'
    CLOUD_INTELLIGENCE = 'cloud_intelligence'
    GITHUB_INTELLIGENCE = 'github_intelligence'
    API_INTELLIGENCE = 'api_intelligence'
    UNKNOWN = 'unknown'

    CHOICES = [
        (DNS_INTELLIGENCE, _('DNS Intelligence')),
        (CERTIFICATE_INTELLIGENCE, _('Certificate Intelligence')),
        (DOMAIN_INTELLIGENCE, _('Domain Intelligence')),
        (ASSET_DISCOVERY, _('Asset Discovery')),
        (TECHNOLOGY_DETECTION, _('Technology Detection')),
        (EMAIL_SECURITY, _('Email Security')),
        (HTTP_SECURITY, _('HTTP Security')),
        (REPUTATION_INTELLIGENCE, _('Reputation Intelligence')),
        (BREACH_INTELLIGENCE, _('Breach Intelligence')),
        (CLOUD_INTELLIGENCE, _('Cloud Intelligence')),
        (GITHUB_INTELLIGENCE, _('GitHub Intelligence')),
        (API_INTELLIGENCE, _('API Intelligence')),
        (UNKNOWN, _('Unknown')),
    ]

    ALL_LAYERS = [
        DNS_INTELLIGENCE,
        CERTIFICATE_INTELLIGENCE,
        DOMAIN_INTELLIGENCE,
        ASSET_DISCOVERY,
        TECHNOLOGY_DETECTION,
        EMAIL_SECURITY,
        HTTP_SECURITY,
        REPUTATION_INTELLIGENCE,
        BREACH_INTELLIGENCE,
        CLOUD_INTELLIGENCE,
        GITHUB_INTELLIGENCE,
        API_INTELLIGENCE,
    ]


class TrustScoreStatus:
    EXCELLENT = 'excellent'
    GOOD = 'good'
    FAIR = 'fair'
    POOR = 'poor'
    CRITICAL = 'critical'

    CHOICES = [
        (EXCELLENT, _('Excellent')),
        (GOOD, _('Good')),
        (FAIR, _('Fair')),
        (POOR, _('Poor')),
        (CRITICAL, _('Critical')),
    ]

    RANGES = {
        EXCELLENT: (90, 100),
        GOOD: (70, 89),
        FAIR: (50, 69),
        POOR: (30, 49),
        CRITICAL: (0, 29),
    }

    COLORS = {
        EXCELLENT: '#10B981',
        GOOD: '#3B82F6',
        FAIR: '#F59E0B',
        POOR: '#EF4444',
        CRITICAL: '#7F1D1D',
    }


class Dimension:
    EMAIL_SECURITY = 'email_security'
    INFRASTRUCTURE_HYGIENE = 'infrastructure_hygiene'
    EXPOSURE_SURFACE = 'exposure_surface'
    BREACH_HISTORY = 'breach_history'
    REPUTATION_TRUST = 'reputation_trust'
    IDENTITY_INTEGRITY = 'identity_integrity'

    CHOICES = [
        (EMAIL_SECURITY, _('Email Security')),
        (INFRASTRUCTURE_HYGIENE, _('Infrastructure Hygiene')),
        (EXPOSURE_SURFACE, _('Exposure Surface')),
        (BREACH_HISTORY, _('Breach History')),
        (REPUTATION_TRUST, _('Reputation & Trust')),
        (IDENTITY_INTEGRITY, _('Identity Integrity')),
    ]

    WEIGHTS = {
        EMAIL_SECURITY: 0.20,
        INFRASTRUCTURE_HYGIENE: 0.15,
        EXPOSURE_SURFACE: 0.15,
        BREACH_HISTORY: 0.15,
        REPUTATION_TRUST: 0.15,
        IDENTITY_INTEGRITY: 0.20,
    }



    DISPLAY_NAMES = {
        EMAIL_SECURITY: 'Email Security',
        INFRASTRUCTURE_HYGIENE: 'Infrastructure Hygiene',
        EXPOSURE_SURFACE: 'Exposure Surface',
        BREACH_HISTORY: 'Breach History',
        REPUTATION_TRUST: 'Reputation & Trust',
        IDENTITY_INTEGRITY: 'Identity Integrity',
    }


class CorrelationRiskLevel:
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'
    LOW = 'low'

    CHOICES = [
        (CRITICAL, _('Critical')),
        (HIGH, _('High')),
        (MEDIUM, _('Medium')),
        (LOW, _('Low')),
    ]

    PENALTIES = {
        CRITICAL: 0.70,
        HIGH: 0.85,
        MEDIUM: 0.95,
        LOW: 1.00,
    }


class SubscriptionPlan:
    FREE = 'free'
    BUSINESS = 'business'
    PRO = 'pro'
    ENTERPRISE = 'enterprise'

    CHOICES = [
        (FREE, _('Free')),
        (BUSINESS, _('Business')),
        (PRO, _('Pro')),
        (ENTERPRISE, _('Enterprise')),
    ]

    LIMITS = {
        FREE: {
            'domains': 1,
            'scans_per_month': 1,
            'scan_frequency': 'monthly',
            'api_access': False,
            'pdf_reports': False,
            'alerts': False,
            'white_label': False,
        },
        BUSINESS: {
            'domains': 3,
            'scans_per_month': 4,
            'scan_frequency': 'weekly',
            'api_access': False,
            'pdf_reports': True,
            'alerts': True,
            'white_label': False,
        },
        PRO: {
            'domains': 10,
            'scans_per_month': 30,
            'scan_frequency': 'daily',
            'api_access': True,
            'pdf_reports': True,
            'alerts': True,
            'white_label': True,
        },
        ENTERPRISE: {
            'domains': -1,
            'scans_per_month': -1,
            'scan_frequency': 'realtime',
            'api_access': True,
            'pdf_reports': True,
            'alerts': True,
            'white_label': True,
        },
    }

    PRICES_KES = {
        FREE: 0,
        BUSINESS: 2500,
        PRO: 7500,
        ENTERPRISE: None,
    }


class ReportFormat:
    EXECUTIVE_SUMMARY = 'executive_summary'
    TECHNICAL_REPORT = 'technical_report'
    COMPLIANCE_REPORT = 'compliance_report'
    API_RESPONSE = 'api_response'
    PDF_CERTIFICATE = 'pdf_certificate'
    DASHBOARD_WIDGET = 'dashboard_widget'

    CHOICES = [
        (EXECUTIVE_SUMMARY, _('Executive Summary')),
        (TECHNICAL_REPORT, _('Technical Report')),
        (COMPLIANCE_REPORT, _('Compliance Report')),
        (API_RESPONSE, _('API Response')),
        (PDF_CERTIFICATE, _('PDF Certificate')),
        (DASHBOARD_WIDGET, _('Dashboard Widget')),
    ]


class ScanType:
    DOMAIN_FULL = 'domain_full'
    DOMAIN_QUICK = 'domain_quick'
    EMAIL_IDENTITY = 'email_identity'
    SCHEDULED = 'scheduled'
    API_TRIGGERED = 'api_triggered'
    MANUAL = 'manual'

    CHOICES = [
        (DOMAIN_FULL, _('Domain Full Scan')),
        (DOMAIN_QUICK, _('Domain Quick Scan')),
        (EMAIL_IDENTITY, _('Email Identity Scan')),
        (SCHEDULED, _('Scheduled Scan')),
        (API_TRIGGERED, _('API Triggered Scan')),
        (MANUAL, _('Manual Scan')),
    ]


class DNSRecordType:
    A = 'A'
    AAAA = 'AAAA'
    MX = 'MX'
    TXT = 'TXT'
    NS = 'NS'
    SOA = 'SOA'
    CNAME = 'CNAME'
    CAA = 'CAA'
    PTR = 'PTR'
    SRV = 'SRV'
    SPF = 'SPF'
    DMARC = 'DMARC'
    DKIM = 'DKIM'

    CHOICES = [
        (A, 'A Record'),
        (AAAA, 'AAAA Record'),
        (MX, 'MX Record'),
        (TXT, 'TXT Record'),
        (NS, 'NS Record'),
        (SOA, 'SOA Record'),
        (CNAME, 'CNAME Record'),
        (CAA, 'CAA Record'),
        (PTR, 'PTR Record'),
        (SRV, 'SRV Record'),
        (SPF, 'SPF Record'),
        (DMARC, 'DMARC Record'),
        (DKIM, 'DKIM Record'),
    ]


class HTTPHeader:
    HSTS = 'Strict-Transport-Security'
    CSP = 'Content-Security-Policy'
    X_FRAME_OPTIONS = 'X-Frame-Options'
    X_CONTENT_TYPE_OPTIONS = 'X-Content-Type-Options'
    REFERRER_POLICY = 'Referrer-Policy'
    PERMISSIONS_POLICY = 'Permissions-Policy'
    X_XSS_PROTECTION = 'X-XSS-Protection'
    SERVER = 'Server'
    X_POWERED_BY = 'X-Powered-By'
    SET_COOKIE = 'Set-Cookie'

    SECURITY_HEADERS = [
        HSTS,
        CSP,
        X_FRAME_OPTIONS,
        X_CONTENT_TYPE_OPTIONS,
        REFERRER_POLICY,
        PERMISSIONS_POLICY,
        X_XSS_PROTECTION,
    ]


class EmailSecurityRecord:
    SPF = 'spf'
    DKIM = 'dkim'
    DMARC = 'dmarc'
    BIMI = 'bimi'
    MTA_STS = 'mta-sts'
    TLS_RPT = 'tls-rpt'

    CHOICES = [
        (SPF, 'SPF'),
        (DKIM, 'DKIM'),
        (DMARC, 'DMARC'),
        (BIMI, 'BIMI'),
        (MTA_STS, 'MTA-STS'),
        (TLS_RPT, 'TLS-RPT'),
    ]


class ThreatCategory:
    PHISHING = 'phishing'
    MALWARE = 'malware'
    SPAM = 'spam'
    BOTNET = 'botnet'
    C2 = 'command_and_control'
    EXPLOIT = 'exploit'
    VULNERABILITY = 'vulnerability'
    DATA_LEAK = 'data_leak'
    CREDENTIAL_STUFFING = 'credential_stuffing'
    TYPOSQUATTING = 'typosquatting'
    SUBDOMAIN_TAKEOVER = 'subdomain_takeover'
    SSL_STRIPPING = 'ssl_stripping'

    CHOICES = [
        (PHISHING, _('Phishing')),
        (MALWARE, _('Malware')),
        (SPAM, _('Spam')),
        (BOTNET, _('Botnet')),
        (C2, _('Command and Control')),
        (EXPLOIT, _('Exploit')),
        (VULNERABILITY, _('Vulnerability')),
        (DATA_LEAK, _('Data Leak')),
        (CREDENTIAL_STUFFING, _('Credential Stuffing')),
        (TYPOSQUATTING, _('Typo Squatting')),
        (SUBDOMAIN_TAKEOVER, _('Subdomain Takeover')),
        (SSL_STRIPPING, _('SSL Stripping')),
    ]
    choices = CHOICES
    values = [value for value, _ in CHOICES]


class ScanTypeChoices:
    DOMAIN_FULL = ScanType.DOMAIN_FULL
    DOMAIN_QUICK = ScanType.DOMAIN_QUICK
    EMAIL_IDENTITY = ScanType.EMAIL_IDENTITY
    SCHEDULED = ScanType.SCHEDULED
    API_TRIGGERED = ScanType.API_TRIGGERED
    MANUAL = ScanType.MANUAL
    choices = ScanType.CHOICES
    values = [value for value, _ in choices]


class ReportTypeChoices:
    EXECUTIVE_SUMMARY = 'executive_summary'
    TECHNICAL_REPORT = 'technical_report'
    COMPLIANCE_REPORT = 'compliance_report'
    API_RESPONSE = 'api_response'
    PDF_CERTIFICATE = 'pdf_certificate'
    DASHBOARD_WIDGET = 'dashboard_widget'
    choices = [
        (EXECUTIVE_SUMMARY, _('Executive Summary')),
        (TECHNICAL_REPORT, _('Technical Report')),
        (COMPLIANCE_REPORT, _('Compliance Report')),
        (API_RESPONSE, _('API Response')),
        (PDF_CERTIFICATE, _('PDF Certificate')),
        (DASHBOARD_WIDGET, _('Dashboard Widget')),
    ]
    values = [value for value, _ in choices]


class ReportFormatChoices:
    EXECUTIVE_SUMMARY = ReportFormat.EXECUTIVE_SUMMARY
    TECHNICAL_REPORT = ReportFormat.TECHNICAL_REPORT
    COMPLIANCE_REPORT = ReportFormat.COMPLIANCE_REPORT
    API_RESPONSE = ReportFormat.API_RESPONSE
    PDF_CERTIFICATE = ReportFormat.PDF_CERTIFICATE
    DASHBOARD_WIDGET = ReportFormat.DASHBOARD_WIDGET
    choices = ReportFormat.CHOICES
    values = [value for value, _ in choices]


class PlanTierChoices:
    FREE = 'free'
    BUSINESS = 'business'
    PRO = 'pro'
    ENTERPRISE = 'enterprise'
    choices = SubscriptionPlan.CHOICES
    values = [value for value, _ in choices]
    LIMITS = SubscriptionPlan.LIMITS
    PRICES_KES = SubscriptionPlan.PRICES_KES


class BillingCycleChoices:
    MONTHLY = 'monthly'
    YEARLY = 'yearly'
    choices = [
        (MONTHLY, _('Monthly')),
        (YEARLY, _('Yearly')),
    ]
    values = [value for value, _ in choices]


class PaymentStatusChoices:
    PENDING = 'pending'
    PROCESSING = 'processing'
    COMPLETED = 'completed'
    FAILED = 'failed'
    REFUNDED = 'refunded'
    choices = [
        (PENDING, _('Pending')),
        (PROCESSING, _('Processing')),
        (COMPLETED, _('Completed')),
        (FAILED, _('Failed')),
        (REFUNDED, _('Refunded')),
    ]
    values = [value for value, _ in choices]


class ScanStatusChoices:
    PENDING = ScanStatus.PENDING
    AUTHORIZING = ScanStatus.AUTHORIZING
    AUTHORIZED = ScanStatus.AUTHORIZED
    DISCOVERING = ScanStatus.DISCOVERING
    RECONNAISSING = ScanStatus.RECONNAISSING
    CORRELATING = ScanStatus.CORRELATING
    SCORING = ScanStatus.SCORING
    INTELLIGENCING = ScanStatus.INTELLIGENCING
    REPORTING = ScanStatus.REPORTING
    COMPLETED = ScanStatus.COMPLETED
    FAILED = ScanStatus.FAILED
    CANCELLED = ScanStatus.CANCELLED
    TIMEOUT = ScanStatus.TIMEOUT
    SUSPENDED = ScanStatus.SUSPENDED
    choices = ScanStatus.CHOICES
    TERMINAL_STATES = ScanStatus.TERMINAL_STATES
    ACTIVE_STATES = ScanStatus.ACTIVE_STATES


class AuthorizationStatusChoices:
    UNVERIFIED = AuthorizationStatus.UNVERIFIED
    PENDING_VERIFICATION = AuthorizationStatus.PENDING_VERIFICATION
    VERIFIED = AuthorizationStatus.VERIFIED
    AUTHORIZED = AuthorizationStatus.AUTHORIZED
    SUSPENDED = AuthorizationStatus.SUSPENDED
    REVOKED = AuthorizationStatus.REVOKED
    EXPIRED = AuthorizationStatus.EXPIRED
    choices = AuthorizationStatus.CHOICES
    SCANNABLE_STATES = AuthorizationStatus.SCANNABLE_STATES


class VerificationMethodChoices:
    DNS_TXT = VerificationMethod.DNS_TXT
    HTML_FILE = VerificationMethod.HTML_FILE
    META_TAG = VerificationMethod.META_TAG
    EMAIL = VerificationMethod.EMAIL
    choices = VerificationMethod.CHOICES


class SeverityChoices:
    INFO = Severity.INFO
    LOW = Severity.LOW
    MEDIUM = Severity.MEDIUM
    HIGH = Severity.HIGH
    CRITICAL = Severity.CRITICAL
    choices = Severity.CHOICES
    WEIGHTS = Severity.WEIGHTS
    ORDER = Severity.ORDER


class SignalTypeChoices:
    PRESENCE = SignalType.PRESENCE
    ABSENCE = SignalType.ABSENCE
    MISCONFIGURATION = SignalType.MISCONFIGURATION
    EXPIRATION = SignalType.EXPIRATION
    EXPOSURE = SignalType.EXPOSURE
    BREACH = SignalType.BREACH
    REPUTATION = SignalType.REPUTATION
    VULNERABILITY = SignalType.VULNERABILITY
    choices = SignalType.CHOICES


class AssetTypeChoices:
    DOMAIN = AssetType.DOMAIN
    SUBDOMAIN = AssetType.SUBDOMAIN
    IP_ADDRESS = AssetType.IP_ADDRESS
    EMAIL = AssetType.EMAIL
    CERTIFICATE = AssetType.CERTIFICATE
    API_ENDPOINT = AssetType.API_ENDPOINT
    REPOSITORY = AssetType.REPOSITORY
    PORT_SERVICE = AssetType.PORT_SERVICE
    CLOUD_RESOURCE = AssetType.CLOUD_RESOURCE
    choices = AssetType.CHOICES


class SourceLayerChoices:
    DNS_INTELLIGENCE = SourceLayer.DNS_INTELLIGENCE
    CERTIFICATE_INTELLIGENCE = SourceLayer.CERTIFICATE_INTELLIGENCE
    DOMAIN_INTELLIGENCE = SourceLayer.DOMAIN_INTELLIGENCE
    ASSET_DISCOVERY = SourceLayer.ASSET_DISCOVERY
    TECHNOLOGY_DETECTION = SourceLayer.TECHNOLOGY_DETECTION
    EMAIL_SECURITY = SourceLayer.EMAIL_SECURITY
    HTTP_SECURITY = SourceLayer.HTTP_SECURITY
    REPUTATION_INTELLIGENCE = SourceLayer.REPUTATION_INTELLIGENCE
    BREACH_INTELLIGENCE = SourceLayer.BREACH_INTELLIGENCE
    CLOUD_INTELLIGENCE = SourceLayer.CLOUD_INTELLIGENCE
    GITHUB_INTELLIGENCE = SourceLayer.GITHUB_INTELLIGENCE
    API_INTELLIGENCE = SourceLayer.API_INTELLIGENCE
    UNKNOWN = SourceLayer.UNKNOWN
    choices = SourceLayer.CHOICES
    ALL_LAYERS = SourceLayer.ALL_LAYERS


class TrustScoreStatusChoices:
    EXCELLENT = TrustScoreStatus.EXCELLENT
    GOOD = TrustScoreStatus.GOOD
    FAIR = TrustScoreStatus.FAIR
    POOR = TrustScoreStatus.POOR
    CRITICAL = TrustScoreStatus.CRITICAL
    choices = TrustScoreStatus.CHOICES
    RANGES = TrustScoreStatus.RANGES
    COLORS = TrustScoreStatus.COLORS


class DimensionChoices:
    EMAIL_SECURITY = Dimension.EMAIL_SECURITY
    INFRASTRUCTURE_HYGIENE = Dimension.INFRASTRUCTURE_HYGIENE
    EXPOSURE_SURFACE = Dimension.EXPOSURE_SURFACE
    BREACH_HISTORY = Dimension.BREACH_HISTORY
    REPUTATION_TRUST = Dimension.REPUTATION_TRUST
    IDENTITY_INTEGRITY = Dimension.IDENTITY_INTEGRITY
    choices = Dimension.CHOICES
    WEIGHTS = Dimension.WEIGHTS


class IndustryChoices:
    TECHNOLOGY = 'technology'
    FINANCIAL_SERVICES = 'financial_services'
    HEALTHCARE = 'healthcare'
    RETAIL = 'retail'
    GOVERNMENT = 'government'
    EDUCATION = 'education'
    MANUFACTURING = 'manufacturing'
    MEDIA = 'media'
    ENERGY = 'energy'
    OTHER = 'other'
    choices = [
        (TECHNOLOGY, _('Technology')),
        (FINANCIAL_SERVICES, _('Financial Services')),
        (HEALTHCARE, _('Healthcare')),
        (RETAIL, _('Retail')),
        (GOVERNMENT, _('Government')),
        (EDUCATION, _('Education')),
        (MANUFACTURING, _('Manufacturing')),
        (MEDIA, _('Media')),
        (ENERGY, _('Energy')),
        (OTHER, _('Other')),
    ]
    values = [value for value, _ in choices]


class ComplianceLevelChoices:
    NOT_ASSESSED = 'not_assessed'
    COMPLIANT = 'compliant'
    PARTIALLY_COMPLIANT = 'partially_compliant'
    NON_COMPLIANT = 'non_compliant'
    choices = [
        (NOT_ASSESSED, _('Not Assessed')),
        (COMPLIANT, _('Compliant')),
        (PARTIALLY_COMPLIANT, _('Partially Compliant')),
        (NON_COMPLIANT, _('Non Compliant')),
    ]
    values = [value for value, _ in choices]


class TrendDirectionChoices:
    IMPROVING = 'improving'
    DECLINING = 'declining'
    STABLE = 'stable'
    UNKNOWN = 'unknown'
    choices = [
        (IMPROVING, _('Improving')),
        (DECLINING, _('Declining')),
        (STABLE, _('Stable')),
        (UNKNOWN, _('Unknown')),
    ]
    values = [value for value, _ in choices]


class TLDCategoryChoices:
    BRAND = 'brand'
    GENERIC = 'generic'
    SPONSORED = 'sponsored'
    COUNTRY_CODE = 'country_code'
    NEW_GTLD = 'new_gtld'
    UNKNOWN = 'unknown'
    choices = [
        (BRAND, _('Brand')),
        (GENERIC, _('Generic')),
        (SPONSORED, _('Sponsored')),
        (COUNTRY_CODE, _('Country Code')),
        (NEW_GTLD, _('New GTLD')),
        (UNKNOWN, _('Unknown')),
    ]
    values = [value for value, _ in choices]


class RiskLevelChoices:
    CRITICAL = CorrelationRiskLevel.CRITICAL
    HIGH = CorrelationRiskLevel.HIGH
    MEDIUM = CorrelationRiskLevel.MEDIUM
    LOW = CorrelationRiskLevel.LOW
    choices = CorrelationRiskLevel.CHOICES
    PENALTIES = CorrelationRiskLevel.PENALTIES


class CorrelationPatternChoices:
    EMAIL_SPOOFING = 'email_spoofing'
    CERTIFICATE_EXPIRY = 'certificate_expiry'
    SUBDOMAIN_TAKEOVER = 'subdomain_takeover'
    DNS_MISCONFIGURATION = 'dns_misconfiguration'
    STALE_HTTP_SECURITY = 'stale_http_security'
    EXPOSED_PORTS = 'exposed_ports'
    choices = [
        (EMAIL_SPOOFING, _('Email Spoofing')),
        (CERTIFICATE_EXPIRY, _('Certificate Expiry')),
        (SUBDOMAIN_TAKEOVER, _('Subdomain Takeover')),
        (DNS_MISCONFIGURATION, _('DNS Misconfiguration')),
        (STALE_HTTP_SECURITY, _('Stale HTTP Security')),
        (EXPOSED_PORTS, _('Exposed Ports')),
    ]
    values = [value for value, _ in choices]


class RemediationPriorityChoices:
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    choices = [
        (LOW, _('Low')),
        (MEDIUM, _('Medium')),
        (HIGH, _('High')),
        (CRITICAL, _('Critical')),
    ]
    values = [value for value, _ in choices]


class SignalCategoryChoices:
    SECURITY_CONTROL_ABSENT = 'SECURITY_CONTROL_ABSENT'
    SECURITY_CONTROL_MISCONFIGURED = 'SECURITY_CONTROL_MISCONFIGURED'
    CERTIFICATE_INVALID = 'CERTIFICATE_INVALID'
    CONFIGURATION = 'CONFIGURATION'
    EXPOSURE = 'EXPOSURE'
    REPUTATION = 'REPUTATION'
    THREAT = 'THREAT'
    COMPLIANCE = 'COMPLIANCE'
    choices = [
        (SECURITY_CONTROL_ABSENT, _('Security Control Absent')),
        (SECURITY_CONTROL_MISCONFIGURED, _('Security Control Misconfigured')),
        (CERTIFICATE_INVALID, _('Certificate Invalid')),
        (CONFIGURATION, _('Configuration')),
        (EXPOSURE, _('Exposure')),
        (REPUTATION, _('Reputation')),
        (THREAT, _('Threat')),
        (COMPLIANCE, _('Compliance')),
    ]
    values = [value for value, _ in choices]