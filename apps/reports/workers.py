from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from apps.reports.generators import ReportGenerator
from apps.core.exceptions import ReportGenerationError


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def generate_reports(self, scan_job_id: str):
    from apps.scanner.models import ScanJob
    from apps.reports.models import TrustReport, ReportTemplate
    from apps.reports.generators import ReportGenerator
    from apps.scoring.models import TrustScore
    from apps.correlation.models import Correlation
    from apps.reconnaissance.models import Finding
    from apps.intelligence.models import IntelligenceBrief
    
    try:
        scan_job = ScanJob.objects.get(id=scan_job_id)
    except ScanJob.DoesNotExist:
        raise ReportGenerationError(f"Scan job {scan_job_id} not found")
    
    scan_job.start_phase('reporting')
    
    trust_score = TrustScore.objects.filter(scan_job=scan_job).first()
    if not trust_score:
        raise ReportGenerationError("No trust score found for scan job")
    
    findings = Finding.objects.filter(scan_job=scan_job, is_deleted=False)
    correlations = Correlation.objects.filter(scan_job=scan_job, is_deleted=False)
    brief = IntelligenceBrief.objects.filter(scan_job=scan_job).first()
    
    generator = ReportGenerator()
    
    report_types = [
        ('executive_summary', 'Executive Summary', 'pdf'),
        ('technical_report', 'Technical Report', 'pdf'),
        ('api_response', 'API Response', 'json'),
    ]
    
    generated_reports = []
    
    for report_type, title, format in report_types:
        try:
            report_data = generator.generate(
                trust_score=trust_score,
                correlations=correlations,
                brief=brief,
                findings=findings,
                scan_job=scan_job,
                report_type=report_type,
                format=format,
            )
            
            trust_report = TrustReport.objects.create(
                scan_job=scan_job,
                domain=scan_job.domain,
                trust_score=trust_score,
                report_type=report_type,
                format=format,
                title=f"{title} - {scan_job.domain.name}",
                content_html=report_data.get('html', ''),
                content_json=report_data.get('json', {}),
                status='completed',
                generation_time_ms=report_data.get('generation_time_ms', 0),
            )
            
            generated_reports.append({
                'type': report_type,
                'report_id': str(trust_report.id),
                'title': title,
            })
            
        except Exception as e:
            TrustReport.objects.create(
                scan_job=scan_job,
                domain=scan_job.domain,
                trust_score=trust_score,
                report_type=report_type,
                format=format,
                title=f"{title} - {scan_job.domain.name}",
                status='failed',
                error_message=str(e),
            )
            generated_reports.append({
                'type': report_type,
                'status': 'failed',
                'error': str(e),
            })
    
    scan_job.reports_generated = generated_reports
    scan_job.reporting_completed_at = timezone.now()
    scan_job.transition_to('completed')
    
    return {
        'status': 'completed',
        'scan_job_id': scan_job_id,
        'reports': generated_reports,
    }


@shared_task
def deliver_report(report_id: str, method: str, recipient: str, webhook_url: str = None, webhook_secret: str = None):
    from apps.reports.models import TrustReport, ReportDelivery
    import requests
    import hmac
    import hashlib
    
    try:
        report = TrustReport.objects.get(id=report_id)
    except TrustReport.DoesNotExist:
        return {'status': 'failed', 'error': 'Report not found'}
    
    delivery = ReportDelivery.objects.create(
        report=report,
        method=method,
        recipient=recipient,
        status='pending',
    )
    
    try:
        if method == 'email':
            _deliver_email(report, recipient)
        elif method == 'webhook':
            _deliver_webhook(report, webhook_url, webhook_secret)
        elif method == 'download':
            delivery.status = 'delivered'
            delivery.delivered_at = timezone.now()
            delivery.save()
            return {'status': 'completed', 'message': 'Download link ready'}
        
        delivery.status = 'delivered'
        delivery.delivered_at = timezone.now()
        delivery.save()
        
        report.delivered_at = timezone.now()
        report.delivery_method = method
        report.save(update_fields=['delivered_at', 'delivery_method'])
        
        return {'status': 'completed', 'delivery_id': str(delivery.id)}
        
    except Exception as e:
        delivery.status = 'failed'
        delivery.error_message = str(e)
        delivery.save()
        raise


def _deliver_email(report, recipient):
    from django.core.mail import EmailMultiAlternatives
    from django.template.loader import render_to_string
    
    subject = f"TrustScan Report: {report.title}"
    
    text_content = f"""
    TrustScan Digital Trust Report
    
    Domain: {report.domain.name}
    Report Type: {report.get_report_type_display()}
    Generated: {report.generated_at.strftime('%B %d, %Y %H:%M')}
    
    Trust Score: {report.trust_score.overall}/100 ({report.trust_score.status})
    
    View the full report in your TrustScan dashboard.
    """
    
    html_content = report.content_html or f"""
    <html>
    <body>
        <h1>TrustScan Report: {report.title}</h1>
        <p>Domain: {report.domain.name}</p>
        <p>Trust Score: {report.trust_score.overall}/100 ({report.trust_score.status})</p>
        <p>Generated: {report.generated_at.strftime('%B %d, %Y %H:%M')}</p>
        <p><a href="{settings.FRONTEND_URL}/reports/{report.id}">View Full Report</a></p>
    </body>
    </html>
    """
    
    email = EmailMultiAlternatives(
        subject=subject,
        body=text_content,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[recipient],
    )
    email.attach_alternative(html_content, "text/html")
    
    if report.file:
        email.attach_file(report.file.path)
    
    email.send()


def _deliver_webhook(report, webhook_url, webhook_secret):
    import requests
    import hmac
    import hashlib
    import json
    
    payload = {
        'report_id': str(report.id),
        'domain': report.domain.name,
        'report_type': report.report_type,
        'format': report.format,
        'trust_score': {
            'overall': report.trust_score.overall,
            'status': report.trust_score.status,
            'dimensions': report.trust_score.dimensions,
        },
        'generated_at': report.generated_at.isoformat(),
        'download_url': f"{settings.FRONTEND_URL}/reports/{report.id}/download",
    }
    
    headers = {'Content-Type': 'application/json'}
    
    if webhook_secret:
        signature = hmac.new(
            webhook_secret.encode(),
            json.dumps(payload).encode(),
            hashlib.sha256
        ).hexdigest()
        headers['X-TrustScan-Signature'] = signature
    
    response = requests.post(webhook_url, json=payload, headers=headers, timeout=30)
    response.raise_for_status()


@shared_task
def process_scheduled_reports():
    from apps.reports.models import ReportSchedule
    from apps.scanner.models import ScanJob
    
    now = timezone.now()
    due_schedules = ReportSchedule.objects.filter(
        is_active=True,
        next_run__lte=now
    )
    
    for schedule in due_schedules:
        latest_scan = ScanJob.objects.filter(
            domain=schedule.domain,
            status='completed'
        ).order_by('-completed_at').first()
        
        if latest_scan:
            generate_reports.delay(str(latest_scan.id))
        
        schedule.last_run = now
        if schedule.frequency == 'daily':
            schedule.next_run = now + timezone.timedelta(days=1)
        elif schedule.frequency == 'weekly':
            schedule.next_run = now + timezone.timedelta(weeks=1)
        elif schedule.frequency == 'monthly':
            from dateutil.relativedelta import relativedelta
            schedule.next_run = now + relativedelta(months=1)
        elif schedule.frequency == 'quarterly':
            from dateutil.relativedelta import relativedelta
            schedule.next_run = now + relativedelta(months=3)
        schedule.save(update_fields=['last_run', 'next_run'])
    
    return f'Processed {due_schedules.count()} scheduled reports'


@shared_task
def cleanup_old_reports():
    from apps.reports.models import TrustReport
    from django.utils import timezone
    from datetime import timedelta
    
    cutoff = timezone.now() - timedelta(days=90)
    
    deleted, _ = TrustReport.objects.filter(
        generated_at__lt=cutoff,
        is_public=False
    ).delete()
    
    return f'Cleaned up {deleted} old reports'