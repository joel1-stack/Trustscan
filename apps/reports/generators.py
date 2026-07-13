from django.template.loader import render_to_string
from django.utils import timezone
from typing import Dict, Any, List
import json
import time


class ReportGenerator:
    def __init__(self):
        self.start_time = None
    
    def generate(
        self,
        trust_score,
        correlations,
        brief,
        findings,
        scan_job,
        report_type: str = 'executive_summary',
        format: str = 'pdf',
    ) -> Dict[str, Any]:
        self.start_time = time.time()
        
        context = self._build_context(
            trust_score=trust_score,
            correlations=correlations,
            brief=brief,
            findings=findings,
            scan_job=scan_job,
        )
        
        if report_type == 'executive_summary':
            return self._generate_executive(context, format)
        elif report_type == 'technical_report':
            return self._generate_technical(context, format)
        elif report_type == 'compliance_report':
            return self._generate_compliance(context, format)
        elif report_type == 'api_response':
            return self._generate_api_response(context, format)
        else:
            return {'error': f'Unknown report type: {report_type}'}
    
    def _build_context(
        self,
        trust_score,
        correlations,
        brief,
        findings,
        scan_job,
    ) -> Dict[str, Any]:
        domain = scan_job.domain
        
        severity_counts = {
            'critical': findings.filter(severity='critical').count(),
            'high': findings.filter(severity='high').count(),
            'medium': findings.filter(severity='medium').count(),
            'low': findings.filter(severity='low').count(),
            'info': findings.filter(severity='info').count(),
        }
        
        findings_by_dimension = {}
        for f in findings.select_related('asset'):
            dim = f.dimension
            if dim not in findings_by_dimension:
                findings_by_dimension[dim] = []
            findings_by_dimension[dim].append({
                'id': str(f.id),
                'title': f.title,
                'severity': f.severity,
                'description': f.finding_summary,
                'asset': f.asset_value,
                'asset_type': f.asset_type,
                'remediation': f.remediation_action,
                'impact_score': f.impact_score,
            })
        
        correlations_data = []
        for c in correlations:
            correlations_data.append({
                'id': str(c.id),
                'pattern_id': c.pattern_id,
                'name': c.pattern_name,
                'risk_level': c.risk_level,
                'narrative': c.narrative,
                'affected_dimensions': c.affected_dimensions,
                'remediation_steps': c.remediation_steps,
                'estimated_impact': c.estimated_score_impact,
            })
        
        brief_data = None
        if brief:
            brief_data = {
                'benchmarks': {
                    'industry': brief.industry,
                    'industry_average': float(brief.industry_average),
                    'industry_percentile': brief.industry_percentile,
                    'tld_average': float(brief.tld_average),
                    'tld_percentile': brief.tld_percentile,
                },
                'trends': {
                    'previous_score': brief.previous_score,
                    'score_change': brief.score_change,
                    'trend_direction': brief.trend_direction,
                    'new_findings': brief.new_findings,
                    'resolved_findings': brief.resolved_findings,
                },
                'threat_context': {
                    'active_campaigns': brief.active_campaigns,
                    'new_cves': brief.new_cves,
                    'regional_threats': brief.regional_threats,
                },
                'regulatory_status': {
                    'regulation': brief.regulation,
                    'compliance_level': brief.compliance_level,
                    'gaps': brief.compliance_gaps,
                },
                'predictions': {
                    'risk_window': brief.risk_window,
                    'incident_probability': float(brief.incident_probability),
                    'primary_risk_vector': brief.primary_risk_vector,
                    'mitigation_urgency': brief.mitigation_urgency,
                },
            }
        
        return {
            'scan_job': {
                'id': str(scan_job.id),
                'domain': domain.name,
                'scan_type': scan_job.scan_type,
                'started_at': scan_job.started_at,
                'completed_at': scan_job.completed_at,
                'duration_seconds': scan_job.duration_seconds,
            },
            'trust_score': {
                'overall': trust_score.overall,
                'status': trust_score.status,
                'confidence': trust_score.confidence,
                'dimensions': trust_score.dimensions,
                'calculated_at': trust_score.calculated_at,
                'scoring_version': trust_score.scoring_version,
            },
            'severity_counts': severity_counts,
            'total_findings': sum(severity_counts.values()),
            'findings_by_dimension': findings_by_dimension,
            'correlations': correlations_data,
            'brief': brief_data,
            'top_risks': trust_score.top_risks,
            'top_actions': trust_score.top_actions,
        }
    
    def _generate_executive(self, context: Dict, format: str) -> Dict:
        generation_time = int((time.time() - self.start_time) * 1000)
        
        html = self._render_executive_html(context)
        json_data = {
            'report_type': 'executive_summary',
            'format': format,
            'trust_score': context['trust_score'],
            'severity_summary': context['severity_counts'],
            'top_risks': context['top_risks'],
            'top_actions': context['top_actions'],
            'benchmarks': context.get('brief', {}).get('benchmarks', {}),
        }
        
        return {
            'html': html,
            'json': json_data,
            'generation_time_ms': generation_time,
        }
    
    def _generate_technical(self, context: Dict, format: str) -> Dict:
        generation_time = int((time.time() - self.start_time) * 1000)
        
        html = self._render_technical_html(context)
        json_data = {
            'report_type': 'technical_report',
            'format': format,
            'scan_job': context['scan_job'],
            'trust_score': context['trust_score'],
            'severity_counts': context['severity_counts'],
            'findings_by_dimension': context['findings_by_dimension'],
            'correlations': context['correlations'],
            'brief': context.get('brief'),
        }
        
        return {
            'html': html,
            'json': json_data,
            'generation_time_ms': generation_time,
        }
    
    def _generate_compliance(self, context: Dict, format: str) -> Dict:
        generation_time = int((time.time() - self.start_time) * 1000)
        
        brief = context.get('brief', {})
        regulatory = brief.get('regulatory_status', {})
        
        html = self._render_compliance_html(context)
        json_data = {
            'report_type': 'compliance_report',
            'format': format,
            'regulation': regulatory.get('regulation', 'Kenya Data Protection Act 2019'),
            'compliance_level': regulatory.get('compliance_level', 'partial'),
            'gaps': regulatory.get('gaps', []),
            'trust_score': context['trust_score'],
            'relevant_findings': [
                f for dim, findings in context['findings_by_dimension'].items()
                for f in findings
            ],
        }
        
        return {
            'html': html,
            'json': json_data,
            'generation_time_ms': generation_time,
        }
    
    def _generate_api_response(self, context: Dict, format: str) -> Dict:
        generation_time = int((time.time() - self.start_time) * 1000)
        
        json_data = {
            'domain': context['scan_job']['domain'],
            'scan_id': context['scan_job']['id'],
            'status': 'COMPLETED',
            'trust_score': {
                'overall': context['trust_score']['overall'],
                'dimensions': context['trust_score']['dimensions'],
            },
            'critical_findings': context['severity_counts']['critical'],
            'high_findings': context['severity_counts']['high'],
            'correlations': [
                {
                    'pattern_id': c['pattern_id'],
                    'name': c['name'],
                    'risk_level': c['risk_level'],
                }
                for c in context['correlations']
            ],
            'recommendations': context['top_actions'],
            'benchmarks': context.get('brief', {}).get('benchmarks', {}),
        }
        
        return {
            'html': '',
            'json': json_data,
            'generation_time_ms': generation_time,
        }
    
    def _render_executive_html(self, context: Dict) -> str:
        trust_score = context['trust_score']
        score = trust_score['overall']
        status = trust_score['status']
        
        status_colors = {
            'excellent': '#10B981',
            'good': '#3B82F6',
            'fair': '#F59E0B',
            'poor': '#EF4444',
            'critical': '#7F1D1D',
        }
        
        color = status_colors.get(status, '#6B7280')
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TrustScan Executive Summary - {context['scan_job']['domain']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f9fafb; color: #1f2937; line-height: 1.6; }}
        .container {{ max-width: 800px; margin: 0 auto; padding: 40px 24px; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .logo {{ font-size: 28px; font-weight: 700; color: #1e40af; margin-bottom: 8px; }}
        .tagline {{ color: #6b7280; font-size: 16px; }}
        .score-badge {{ display: inline-block; padding: 32px 64px; border-radius: 16px; text-align: center; margin: 24px 0; background: {color}; }}
        .score-number {{ font-size: 80px; font-weight: 800; line-height: 1; color: white; }}
        .score-label {{ font-size: 20px; opacity: 0.9; color: white; margin-top: 8px; }}
        .section {{ margin: 32px 0; }}
        .section-title {{ font-size: 20px; font-weight: 600; color: #111827; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin: 24px 0; }}
        .summary-card {{ background: white; border: 1px solid #e5e7eb; border-radius: 12px; padding: 20px; text-align: center; }}
        .summary-number {{ font-size: 32px; font-weight: 700; color: #111827; }}
        .summary-label {{ font-size: 14px; color: #6b7280; margin-top: 4px; }}
        .risk-item {{ background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 16px; margin: 12px 0; }}
        .risk-title {{ font-weight: 600; color: #991b1b; }}
        .risk-desc {{ color: #7f1d1d; margin-top: 4px; font-size: 14px; }}
        .action-item {{ background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 16px; margin: 12px 0; }}
        .action-title {{ font-weight: 600; color: #166534; }}
        .action-desc {{ color: #14532d; margin-top: 4px; font-size: 14px; }}
        .dimension-bar {{ margin: 12px 0; }}
        .dimension-label {{ display: flex; justify-content: space-between; margin-bottom: 4px; font-size: 14px; }}
        .dimension-track {{ height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; }}
        .dimension-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
        .footer {{ margin-top: 48px; padding-top: 24px; border-top: 1px solid #e5e7eb; text-align: center; color: #6b7280; font-size: 14px; }}
        .meta-info {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 24px 0; }}
        .meta-item {{ background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; }}
        .meta-label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }}
        .meta-value {{ font-size: 16px; font-weight: 600; color: #111827; margin-top: 4px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">TrustScan</div>
            <div class="tagline">Map and protect your digital business</div>
        </div>
        
        <div class="meta-info">
            <div class="meta-item">
                <div class="meta-label">Domain</div>
                <div class="meta-value">{context['scan_job']['domain']}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan Date</div>
                <div class="meta-value">{context['scan_job']['completed_at'].strftime('%B %d, %Y') if context['scan_job']['completed_at'] else 'N/A'}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Scan Duration</div>
                <div class="meta-value">{context['scan_job']['duration_seconds']}s</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Report Version</div>
                <div class="meta-value">{trust_score['scoring_version']}</div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Overall Trust Score</div>
            <div class="score-badge" style="background: {color};">
                <div class="score-number">{score}</div>
                <div class="score-label">{status.upper()}</div>
            </div>
            <p style="text-align: center; color: #6b7280; margin-top: 16px;">
                Confidence: {trust_score['confidence']}% | Based on {len(context['findings_by_dimension'])} security dimensions
            </p>
        </div>
        
        <div class="section">
            <div class="section-title">Dimension Breakdown</div>
            <div class="dimension-bar">
                <div class="dimension-label"><span>Email Security</span><span>{trust_score['dimensions']['email_security']}</span></div>
                <div class="dimension-track"><div class="dimension-fill" style="width: {trust_score['dimensions']['email_security']}%; background: {color};"></div></div>
            </div>
            <div class="dimension-bar">
                <div class="dimension-label"><span>Infrastructure Hygiene</span><span>{trust_score['dimensions']['infrastructure_hygiene']}</span></div>
                <div class="dimension-track"><div class="dimension-fill" style="width: {trust_score['dimensions']['infrastructure_hygiene']}%; background: {color};"></div></div>
            </div>
            <div class="dimension-bar">
                <div class="dimension-label"><span>Exposure Surface</span><span>{trust_score['dimensions']['exposure_surface']}</span></div>
                <div class="dimension-track"><div class="dimension-fill" style="width: {trust_score['dimensions']['exposure_surface']}%; background: {color};"></div></div>
            </div>
            <div class="dimension-bar">
                <div class="dimension-label"><span>Breach History</span><span>{trust_score['dimensions']['breach_history']}</span></div>
                <div class="dimension-track"><div class="dimension-fill" style="width: {trust_score['dimensions']['breach_history']}%; background: {color};"></div></div>
            </div>
            <div class="dimension-bar">
                <div class="dimension-label"><span>Reputation & Trust</span><span>{trust_score['dimensions']['reputation_trust']}</span></div>
                <div class="dimension-track"><div class="dimension-fill" style="width: {trust_score['dimensions']['reputation_trust']}%; background: {color};"></div></div>
            </div>
            <div class="dimension-bar">
                <div class="dimension-label"><span>Identity Integrity</span><span>{trust_score['dimensions']['identity_integrity']}</span></div>
                <div class="dimension-track"><div class="dimension-fill" style="width: {trust_score['dimensions']['identity_integrity']}%; background: {color};"></div></div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-title">Risk Summary</div>
            <div class="summary-grid">
                <div class="summary-card" style="border-left: 4px solid #7f1d1d;">
                    <div class="summary-number">{context['severity_counts']['critical']}</div>
                    <div class="summary-label">Critical</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid #ef4444;">
                    <div class="summary-number">{context['severity_counts']['high']}</div>
                    <div class="summary-label">High</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid #f59e0b;">
                    <div class="summary-number">{context['severity_counts']['medium']}</div>
                    <div class="summary-label">Medium</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid #3b82f6;">
                    <div class="summary-number">{context['severity_counts']['low']}</div>
                    <div class="summary-label">Low</div>
                </div>
                <div class="summary-card" style="border-left: 4px solid #6b7280;">
                    <div class="summary-number">{context['severity_counts']['info']}</div>
                    <div class="summary-label">Info</div>
                </div>
            </div>
        </div>
"""
        
        if context['top_risks']:
            html += f"""
        <div class="section">
            <div class="section-title">Top Risks</div>
"""
            for risk in context['top_risks'][:5]:
                html += f"""
            <div class="risk-item">
                <div class="risk-title">{risk.get('title', risk.get('pattern', 'Risk'))}</div>
                <div class="risk-desc">{risk.get('description', risk.get('narrative', ''))}</div>
            </div>
"""
            html += "</div>"
        
        if context['top_actions']:
            html += f"""
        <div class="section">
            <div class="section-title">Priority Actions</div>
"""
            for i, action in enumerate(context['top_actions'][:5], 1):
                html += f"""
            <div class="action-item">
                <div class="action-title">#{i} {action.get('action', 'Action required')}</div>
                <div class="action-desc">Impact: +{action.get('impact', 0)} points | Effort: {action.get('effort', 'Medium')}</div>
            </div>
"""
            html += "</div>"
        
        brief = context.get('brief')
        if brief:
            benchmarks = brief.get('benchmarks', {})
            html += f"""
        <div class="section">
            <div class="section-title">Industry Benchmark</div>
            <div class="summary-grid">
                <div class="summary-card">
                    <div class="summary-number">{benchmarks.get('industry_average', 0)}</div>
                    <div class="summary-label">Industry Average</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{benchmarks.get('industry_percentile', 0)}%</div>
                    <div class="summary-label">Your Percentile</div>
                </div>
                <div class="summary-card">
                    <div class="summary-number">{benchmarks.get('tld_average', 0)}</div>
                    <div class="summary-label">TLD Average</div>
                </div>
            </div>
        </div>
"""
        
        html += f"""
        <div class="footer">
            <p>This report was generated by TrustScan on {timezone.now().strftime('%B %d, %Y at %H:%M')}</p>
            <p>TrustScan — Digital Trust Intelligence Platform | <a href="https://trustscan.co.ke" style="color: #1e40af;">trustscan.co.ke</a></p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _render_technical_html(self, context: Dict) -> str:
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TrustScan Technical Report - {context['scan_job']['domain']}</title>
    <style>
        body {{ font-family: monospace; margin: 0; padding: 24px; background: #1e1e1e; color: #d4d4d4; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1, h2, h3 {{ color: #ffffff; }}
        .card {{ background: #252526; border: 1px solid #3c3c3c; border-radius: 8px; padding: 20px; margin: 16px 0; }}
        .finding {{ border-left: 4px solid #f44747; padding: 12px 16px; margin: 8px 0; background: #2d1b1b; }}
        .finding.high {{ border-color: #f44747; }}
        .finding.medium {{ border-color: #cca700; }}
        .finding.low {{ border-color: #3794ff; }}
        .finding.info {{ border-color: #4ec9b0; }}
        pre {{ background: #1e1e1e; padding: 12px; border-radius: 4px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #3c3c3c; }}
        th {{ color: #9cdcfe; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>TrustScan Technical Report</h1>
        <p>Domain: {context['scan_job']['domain']} | Scan ID: {context['scan_job']['id']}</p>
        
        <div class="card">
            <h2>Trust Score Details</h2>
            <p>Overall: {context['trust_score']['overall']}/100 ({context['trust_score']['status']})</p>
            <p>Confidence: {context['trust_score']['confidence']}%</p>
            <table>
                <tr><th>Dimension</th><th>Score</th></tr>
"""
        for dim, score in context['trust_score']['dimensions'].items():
            html += f"<tr><td>{dim.replace('_', ' ').title()}</td><td>{score}</td></tr>"
        
        html += """
            </table>
        </div>
        
        <div class="card">
            <h2>Findings by Dimension</h2>
"""
        for dim, findings in context['findings_by_dimension'].items():
            html += f"<h3>{dim.replace('_', ' ').title()} ({len(findings)} findings)</h3>"
            for f in findings:
                html += f"""
                <div class="finding {f['severity']}">
                    <strong>{f['title']}</strong> [{f['severity'].upper()}]
                    <br>{f['description']}
                    <br><em>Asset: {f['asset']} ({f['asset_type']})</em>
                    <br><em>Remediation: {f['remediation']}</em>
                </div>
"""
        
        html += """
        </div>
        
        <div class="card">
            <h2>Correlations</h2>
"""
        for c in context['correlations']:
            html += f"""
            <div class="finding {c['risk_level']}">
                <strong>{c['name']}</strong> [{c['risk_level'].upper()}]
                <br>{c['narrative']}
                <br><em>Affected: {', '.join(c['affected_dimensions'])}</em>
                <br><em>Remediation: {', '.join(c['remediation_steps'])}</em>
            </div>
"""
        
        html += """
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def _render_compliance_html(self, context: Dict) -> str:
        return self._render_technical_html(context)


def generate_report(trust_score, correlations, brief, findings, scan_job, report_type='executive_summary', format='pdf'):
    generator = ReportGenerator()
    return generator.generate(trust_score, correlations, brief, findings, scan_job, report_type, format)