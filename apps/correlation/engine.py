from typing import List, Dict, Any, Tuple
from apps.reconnaissance.models import Finding
from apps.core.constants import DimensionChoices, SeverityChoices, RiskLevelChoices


class CorrelationEngine:
    RULES = [
        {
            'pattern_id': 'corr-001',
            'name': 'Email Spoofing Chain',
            'description': 'This domain has no email authentication. Anyone can send email appearing to come from this domain.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'dns_intelligence', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'email_security', 'severity': ['high', 'critical']},
                {'source_layer': 'dns_intelligence', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'email_security', 'severity': ['high', 'critical']},
                {'source_layer': 'dns_intelligence', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'email_security', 'severity': ['medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2 AND S3',
            'affected_dimensions': ['email_security', 'reputation_trust'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Add DMARC record with p=reject',
                'Configure SPF with -all mechanism',
                'Set up DKIM selectors for outbound email',
                'Monitor DMARC reports for compliance'
            ],
            'estimated_score_impact': 15,
        },
        {
            'pattern_id': 'corr-002',
            'name': 'Shadow IT Payment',
            'description': 'An unauthorized payment subdomain was discovered. This may be a fraudulent page targeting your customers.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'asset_discovery', 'signal_category': 'ASSET_EXPOSED', 'asset_value_pattern': r'pay|billing|checkout', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
                {'source_layer': 'reconnaissance', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['exposure_surface', 'identity_integrity'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Verify if this payment page is authorized',
                'If unauthorized, take down immediately',
                'Check for phishing content',
                'Report to hosting provider and domain registrar'
            ],
            'estimated_score_impact': 20,
        },
        {
            'pattern_id': 'corr-003',
            'name': 'Certificate Mismatch',
            'description': 'A subdomain serves a certificate for an unrelated domain. Possible subdomain takeover or misconfiguration.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'certificate_intelligence', 'signal_category': 'CERTIFICATE_VALID', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
                {'source_layer': 'certificate_intelligence', 'signal_category': 'SECURITY_CONTROL_MISCONFIGURED', 'severity': ['medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['infrastructure_hygiene', 'identity_integrity'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Verify certificate SAN matches subdomain',
                'Check for dangling CNAME records',
                'Reissue certificate with correct SAN',
                'Monitor for subdomain takeover attempts'
            ],
            'estimated_score_impact': 15,
        },
        {
            'pattern_id': 'corr-004',
            'name': 'Exposed Admin, No MFA',
            'description': 'An admin panel is publicly accessible without transport security or modern software.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'technology_detection', 'signal_category': 'ASSET_EXPOSED', 'asset_value_pattern': r'admin|administrator|panel|dashboard', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
                {'source_layer': 'http_security', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'infrastructure_hygiene', 'severity': ['high', 'critical']},
                {'source_layer': 'technology_detection', 'signal_category': 'SERVICE_VULNERABLE', 'severity': ['medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2 AND S3',
            'affected_dimensions': ['exposure_surface', 'infrastructure_hygiene'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Restrict admin panel access via VPN/IP whitelist',
                'Enable HSTS and security headers',
                'Update outdated software',
                'Implement MFA for all admin access'
            ],
            'estimated_score_impact': 20,
        },
        {
            'pattern_id': 'corr-005',
            'name': 'Breach Cascade',
            'description': 'Multiple compromised credentials plus exposed secrets create a high probability of unauthorized access.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'breach_intelligence', 'signal_category': 'CREDENTIAL_COMPROMISED', 'severity': ['high', 'critical']},
                {'source_layer': 'breach_intelligence', 'signal_category': 'CREDENTIAL_COMPROMISED', 'severity': ['critical']},
                {'source_layer': 'github_intelligence', 'signal_category': 'ASSET_EXPOSED', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2 AND S3',
            'affected_dimensions': ['breach_history', 'exposure_surface'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Force password reset for all affected accounts',
                'Rotate all exposed secrets and API keys',
                'Enable MFA on all accounts',
                'Monitor for credential stuffing attacks'
            ],
            'estimated_score_impact': 15,
        },
        {
            'pattern_id': 'corr-006',
            'name': 'Domain Expiry Risk',
            'description': 'This domain expires soon with exposed ownership details. Hijacking risk is elevated.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'domain_intelligence', 'signal_category': 'SECURITY_CONTROL_MISCONFIGURED', 'dimension': 'identity_integrity', 'severity': ['high', 'critical']},
                {'source_layer': 'domain_intelligence', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['identity_integrity', 'infrastructure_hygiene'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Enable auto-renewal for domain',
                'Set calendar reminder for 60 days before expiry',
                'Consider enabling registrar lock',
                'Verify WHOIS contact information is current'
            ],
            'estimated_score_impact': 10,
        },
        {
            'pattern_id': 'corr-007',
            'name': 'Origin IP Exposure',
            'description': 'Your CDN can be bypassed by targeting the origin IP directly.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'asset_discovery', 'signal_category': 'SECURITY_CONTROL_PRESENT', 'dimension': 'infrastructure_hygiene', 'severity': ['info']},
                {'source_layer': 'asset_discovery', 'signal_category': 'ASSET_EXPOSED', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['infrastructure_hygiene', 'exposure_surface'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Configure CDN to only accept traffic from edge IPs',
                'Use CDN provider WAF to block direct origin access',
                'Change origin IP if already exposed',
                'Enable authenticated origin pulls'
            ],
            'estimated_score_impact': 10,
        },
        {
            'pattern_id': 'corr-008',
            'name': 'Stale Infrastructure',
            'description': 'Vulnerable software with no known breaches yet — a window of active risk.',
            'risk_level': 'medium',
            'required_signals': [
                {'source_layer': 'technology_detection', 'signal_category': 'SERVICE_VULNERABLE', 'severity': ['high', 'critical']},
                {'source_layer': 'breach_intelligence', 'signal_category': 'SECURITY_CONTROL_PRESENT', 'severity': ['info']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['infrastructure_hygiene', 'exposure_surface'],
            'remediation_priority': 3,
            'remediation_steps': [
                'Update to latest secure version',
                'Apply security patches immediately',
                'Implement vulnerability scanning in CI/CD',
                'Monitor for new CVEs affecting this software'
            ],
            'estimated_score_impact': 8,
        },
        {
            'pattern_id': 'corr-009',
            'name': 'API Surface Risk',
            'description': 'Your API is publicly documented and accessible without authentication over insecure transport.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'api_intelligence', 'signal_category': 'ASSET_EXPOSED', 'severity': ['medium', 'high', 'critical']},
                {'source_layer': 'api_intelligence', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'severity': ['high', 'critical']},
                {'source_layer': 'http_security', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'infrastructure_hygiene', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2 AND S3',
            'affected_dimensions': ['exposure_surface', 'infrastructure_hygiene'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Implement authentication for all API endpoints',
                'Enforce HTTPS with HSTS',
                'Remove public API documentation or restrict access',
                'Implement rate limiting and API gateway'
            ],
            'estimated_score_impact': 12,
        },
        {
            'pattern_id': 'corr-010',
            'name': 'Cloud Storage Leak',
            'description': 'Exposed cloud storage combined with valid credentials creates direct data breach path.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'cloud_intelligence', 'signal_category': 'ASSET_EXPOSED', 'severity': ['critical']},
                {'source_layer': 'github_intelligence', 'signal_category': 'CREDENTIAL_COMPROMISED', 'severity': ['critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['exposure_surface', 'breach_history'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Make storage bucket private immediately',
                'Rotate all exposed credentials',
                'Audit access logs for unauthorized access',
                'Implement bucket policies and IAM restrictions'
            ],
            'estimated_score_impact': 20,
        },
        {
            'pattern_id': 'corr-011',
            'name': 'SSL Downgrade Chain',
            'description': 'Legacy TLS supported without downgrade protection. Man-in-the-middle attacks possible.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'certificate_intelligence', 'signal_category': 'SERVICE_VULNERABLE', 'severity': ['high', 'critical']},
                {'source_layer': 'http_security', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'infrastructure_hygiene', 'severity': ['high', 'critical']},
                {'source_layer': 'http_security', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'infrastructure_hygiene', 'severity': ['medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['infrastructure_hygiene', 'exposure_surface'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Disable TLS 1.0 and 1.1',
                'Enable HSTS with preload',
                'Implement CSP header',
                'Configure strong cipher suites only'
            ],
            'estimated_score_impact': 10,
        },
        {
            'pattern_id': 'corr-012',
            'name': 'Email Infrastructure Risk',
            'description': 'Business domain uses personal email provider. Professional email authentication not possible.',
            'risk_level': 'medium',
            'required_signals': [
                {'source_layer': 'email_security', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
                {'source_layer': 'domain_intelligence', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['email_security', 'identity_integrity'],
            'remediation_priority': 3,
            'remediation_steps': [
                'Migrate to professional email provider (Google Workspace, Microsoft 365)',
                'Configure proper SPF, DKIM, DMARC',
                'Set up BIMI for brand recognition',
                'Monitor email deliverability'
            ],
            'estimated_score_impact': 8,
        },
        {
            'pattern_id': 'corr-013',
            'name': 'Subdomain Takeover',
            'description': 'A subdomain points to a service that no longer exists. An attacker can claim it.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'asset_discovery', 'signal_category': 'ASSET_EXPOSED', 'severity': ['high', 'critical']},
                {'source_layer': 'reconnaissance', 'signal_category': 'ASSET_EXPOSED', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['exposure_surface', 'identity_integrity'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Remove dangling CNAME records',
                'Claim the service if still needed',
                'Monitor for new dangling records',
                'Use automated subdomain takeover detection'
            ],
            'estimated_score_impact': 18,
        },
        {
            'pattern_id': 'corr-014',
            'name': 'Data Leak Pipeline',
            'description': 'A publicly accessible API endpoint appears to expose personal data without access controls.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'api_intelligence', 'signal_category': 'ASSET_EXPOSED', 'severity': ['high', 'critical']},
                {'source_layer': 'api_intelligence', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['exposure_surface', 'reputation_trust'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Implement authentication for API endpoints',
                'Add authorization checks for data access',
                'Implement rate limiting',
                'Audit API for PII exposure'
            ],
            'estimated_score_impact': 12,
        },
        {
            'pattern_id': 'corr-015',
            'name': 'CI/CD Exposure',
            'description': 'Your deployment pipeline is publicly visible with embedded credentials and no code review enforcement.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'github_intelligence', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
                {'source_layer': 'github_intelligence', 'signal_category': 'CREDENTIAL_COMPROMISED', 'severity': ['high', 'critical']},
                {'source_layer': 'github_intelligence', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'severity': ['medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2 AND S3',
            'affected_dimensions': ['exposure_surface', 'breach_history'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Make CI/CD repositories private',
                'Remove secrets from code, use secret managers',
                'Enable branch protection rules',
                'Require PR reviews for all changes'
            ],
            'estimated_score_impact': 12,
        },
        {
            'pattern_id': 'corr-016',
            'name': 'Global Phishing Target',
            'description': 'High-value TLD with weak email security targeted by active phishing campaign.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'domain_intelligence', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info']},
                {'source_layer': 'email_security', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'email_security', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['email_security', 'reputation_trust'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Implement full email authentication (SPF, DKIM, DMARC)',
                'Enable DMARC reporting and monitoring',
                'Consider email security gateway',
                'Train employees on phishing awareness'
            ],
            'estimated_score_impact': 15,
        },
        {
            'pattern_id': 'corr-017',
            'name': 'Email Provider Compromise',
            'description': 'Email in breach + provider has known vulnerability.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'breach_intelligence', 'signal_category': 'CREDENTIAL_COMPROMISED', 'severity': ['high', 'critical']},
                {'source_layer': 'reconnaissance', 'signal_category': 'SERVICE_VULNERABLE', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['breach_history', 'email_security'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Change password immediately',
                'Enable MFA on email account',
                'Check for unauthorized forwarding rules',
                'Monitor for suspicious login activity'
            ],
            'estimated_score_impact': 12,
        },
        {
            'pattern_id': 'corr-018',
            'name': 'Cross-Border Data Risk',
            'description': 'Domain hosted outside Kenya + processes Kenyan personal data + no Kenya DPA compliance signals.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'asset_discovery', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info']},
                {'source_layer': 'reconnaissance', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'infrastructure_hygiene', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['infrastructure_hygiene', 'reputation_trust'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Review data residency requirements',
                'Implement Kenya DPA compliant controls',
                'Consider local hosting or data processing agreements',
                'Conduct privacy impact assessment'
            ],
            'estimated_score_impact': 10,
        },
        {
            'pattern_id': 'corr-019',
            'name': 'Typosquatting Network',
            'description': 'Multiple similar domains registered + same registrar + same IP + different TLDs.',
            'risk_level': 'critical',
            'required_signals': [
                {'source_layer': 'asset_discovery', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info']},
                {'source_layer': 'domain_intelligence', 'signal_category': 'SECURITY_CONTROL_MISCONFIGURED', 'severity': ['medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['identity_integrity', 'reputation_trust'],
            'remediation_priority': 1,
            'remediation_steps': [
                'Register defensive domains',
                'Monitor for new typosquat registrations',
                'Report to registrar and hosting providers',
                'Consider trademark protection'
            ],
            'estimated_score_impact': 20,
        },
        {
            'pattern_id': 'corr-020',
            'name': 'Email Reputation Cascade',
            'description': 'Your email is in 2 breaches. If you reused passwords, other accounts are at risk.',
            'risk_level': 'high',
            'required_signals': [
                {'source_layer': 'breach_intelligence', 'signal_category': 'CREDENTIAL_COMPROMISED', 'severity': ['high', 'critical']},
            ],
            'logic': 'S1',
            'affected_dimensions': ['breach_history', 'email_security'],
            'remediation_priority': 2,
            'remediation_steps': [
                'Change any passwords reused from breached accounts',
                'Enable 2FA on email and all important accounts',
                'Use password manager for unique passwords',
                'Monitor for credential stuffing attempts'
            ],
            'estimated_score_impact': 12,
        },
        {
            'pattern_id': 'corr-021',
            'name': 'Provider Downgrade',
            'description': 'Corporate email forwards to consumer email (Gmail) + consumer email has weak security.',
            'risk_level': 'medium',
            'required_signals': [
                {'source_layer': 'email_security', 'signal_category': 'ASSET_EXPOSED', 'severity': ['info', 'low', 'medium', 'high', 'critical']},
                {'source_layer': 'email_security', 'signal_category': 'SECURITY_CONTROL_ABSENT', 'dimension': 'email_security', 'severity': ['medium', 'high', 'critical']},
            ],
            'logic': 'S1 AND S2',
            'affected_dimensions': ['email_security', 'identity_integrity'],
            'remediation_priority': 3,
            'remediation_steps': [
                'Migrate to professional email hosting',
                'Configure proper email authentication',
                'Disable auto-forwarding to consumer email',
                'Implement email security policies'
            ],
            'estimated_score_impact': 8,
        },
    ]
    
    def __init__(self):
        self.findings_cache = {}
    
    def evaluate(self, scan_job) -> Tuple[List[Dict], List[Dict]]:
        from apps.reconnaissance.models import Finding
        
        findings = list(Finding.objects.filter(scan_job=scan_job).select_related('asset'))
        
        self.findings_cache = self._index_findings(findings)
        
        correlations = []
        pattern_matches = []
        
        for rule in self.RULES:
            matched, matched_findings, matched_signals = self._evaluate_rule(rule)
            
            pattern_matches.append({
                'matched_findings': matched_findings,
                'matched_signals': matched_signals,
                'evaluation_result': {
                    'rule_id': rule['pattern_id'],
                    'matched': matched,
                    'conditions_met': len(matched_findings) > 0,
                },
                'matched': matched,
            })
            
            if matched:
                correlations.append(self._create_correlation(scan_job, rule, matched_findings))
        
        return correlations, pattern_matches
    
    def _index_findings(self, findings: List[Finding]) -> Dict:
        indexed = {}
        for f in findings:
            key = (f.source_layer, f.signal_category, f.dimension, f.severity)
            if key not in indexed:
                indexed[key] = []
            indexed[key].append(f)
        return indexed
    
    def _evaluate_rule(self, rule: Dict) -> Tuple[bool, List[str], List[str]]:
        matched_findings = []
        matched_signals = []
        conditions_met = 0
        
        for condition in rule['required_signals']:
            matches = self._find_matching_findings(condition)
            if matches:
                conditions_met += 1
                for m in matches:
                    matched_findings.append(str(m.id))
                    matched_signals.append({
                        'source_layer': m.source_layer,
                        'signal_category': m.signal_category,
                        'severity': m.severity,
                        'dimension': m.dimension,
                        'title': m.title,
                    })
        
        required = len(rule['required_signals'])
        logic = rule.get('logic', 'AND')
        
        if logic == 'AND':
            matched = conditions_met == required
        elif logic == 'OR':
            matched = conditions_met > 0
        else:
            matched = conditions_met >= required // 2 + 1
        
        return matched, matched_findings, matched_signals
    
    def _find_matching_findings(self, condition: Dict) -> List[Finding]:
        matches = []
        source_layer = condition.get('source_layer')
        signal_category = condition.get('signal_category')
        dimension = condition.get('dimension')
        severity = condition.get('severity', [])
        asset_value_pattern = condition.get('asset_value_pattern')
        
        for (sl, sc, dim, sev), findings in self.findings_cache.items():
            if source_layer and sl != source_layer:
                continue
            if signal_category and sc != signal_category:
                continue
            if dimension and dim != dimension:
                continue
            if severity and sev not in severity:
                continue
            if asset_value_pattern:
                import re
                for f in findings:
                    if re.search(asset_value_pattern, f.asset_value, re.IGNORECASE):
                        matches.append(f)
            else:
                matches.extend(findings)
        
        return matches
    
    def _create_correlation(self, scan_job, rule: Dict, matched_findings: List[str]) -> Dict:
        return {
            'scan_job': scan_job,
            'pattern_id': rule['pattern_id'],
            'pattern_name': rule['name'],
            'risk_level': rule['risk_level'],
            'narrative': rule['description'],
            'short_description': rule['name'],
            'contributing_findings': matched_findings,
            'contributing_signals': [],
            'affected_dimensions': rule['affected_dimensions'],
            'remediation_priority': rule['remediation_priority'],
            'remediation_steps': rule['remediation_steps'],
            'estimated_score_impact': rule['estimated_score_impact'],
            'confidence': 85,
        }