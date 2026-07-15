"""
Billing Celery workers — subscriptions, M-Pesa, invoicing.
"""
from celery import shared_task
from django.conf import settings
from django.utils import timezone

from apps.core.exceptions import BillingError


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def create_subscription(self, organization_id: str, plan_tier: str, billing_cycle: str = 'monthly'):
    from apps.accounts.models import Organization
    from apps.billing.models import Plan, Subscription

    try:
        organization = Organization.objects.get(id=organization_id)
    except Organization.DoesNotExist:
        raise BillingError(f'Organization {organization_id} not found')

    try:
        plan = Plan.objects.get(tier=plan_tier, is_active=True)
    except Plan.DoesNotExist:
        raise BillingError(f'Plan {plan_tier} not found')

    trial_days = getattr(plan, 'trial_days', 14)
    subscription, created = Subscription.objects.update_or_create(
        organization=organization,
        defaults={
            'plan': plan,
            'status': 'trial',
            'billing_cycle': billing_cycle,
            'current_period_start': timezone.now(),
            'current_period_end': timezone.now() + timezone.timedelta(days=30),
            'trial_end': timezone.now() + timezone.timedelta(days=trial_days),
        },
    )

    return {
        'status': 'created' if created else 'updated',
        'subscription_id': str(subscription.id),
        'trial_end': subscription.trial_end.isoformat(),
    }


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def process_mpesa_payment(self, payment_id: str):
    import requests
    from apps.billing.models import Payment

    try:
        payment = Payment.objects.get(id=payment_id)
    except Payment.DoesNotExist:
        return {'status': 'error', 'reason': 'payment not found'}

    payment.status = 'processing'
    payment.save(update_fields=['status'])

    try:
        import base64
        from datetime import datetime

        consumer_key = getattr(settings, 'MPESA_CONSUMER_KEY', '')
        consumer_secret = getattr(settings, 'MPESA_CONSUMER_SECRET', '')
        shortcode = getattr(settings, 'MPESA_SHORTCODE', '')
        passkey = getattr(settings, 'MPESA_PASSKEY', '')
        callback_url = getattr(settings, 'MPESA_CALLBACK_URL', '')
        environment = getattr(settings, 'MPESA_ENVIRONMENT', 'sandbox')

        base_url = (
            'https://api.safaricom.co.ke'
            if environment == 'production'
            else 'https://sandbox.safaricom.co.ke'
        )

        # 1. Get access token
        token_resp = requests.get(
            f'{base_url}/oauth/v1/generate?grant_type=client_credentials',
            auth=(consumer_key, consumer_secret),
            timeout=15,
        )
        token_resp.raise_for_status()
        access_token = token_resp.json().get('access_token', '')

        # 2. Build STK push password
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        raw_password = f'{shortcode}{passkey}{timestamp}'
        password = base64.b64encode(raw_password.encode()).decode()

        stk_payload = {
            'BusinessShortCode': shortcode,
            'Password': password,
            'Timestamp': timestamp,
            'TransactionType': 'CustomerPayBillOnline',
            'Amount': int(payment.amount),
            'PartyA': payment.mpesa_phone_number,
            'PartyB': shortcode,
            'PhoneNumber': payment.mpesa_phone_number,
            'CallBackURL': callback_url,
            'AccountReference': f'TRUSTSCAN-{str(payment.id)[:8].upper()}',
            'TransactionDesc': 'TrustScan Subscription Payment',
        }

        stk_resp = requests.post(
            f'{base_url}/mpesa/stkpush/v1/processrequest',
            json=stk_payload,
            headers={
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json',
            },
            timeout=30,
        )
        stk_resp.raise_for_status()
        data = stk_resp.json()

        payment.mpesa_checkout_request_id = data.get('CheckoutRequestID', '')
        payment.provider_response = data
        payment.status = 'pending'
        payment.save(update_fields=['mpesa_checkout_request_id', 'provider_response', 'status'])

        return {'status': 'initiated', 'checkout_request_id': payment.mpesa_checkout_request_id}

    except Exception as exc:
        payment.status = 'failed'
        payment.failure_reason = str(exc)
        payment.failed_at = timezone.now()
        payment.save(update_fields=['status', 'failure_reason', 'failed_at'])
        raise self.retry(exc=exc)


@shared_task
def handle_mpesa_callback(callback_data: dict):
    from apps.billing.models import Payment

    body = callback_data.get('Body', {}).get('stkCallback', callback_data)
    checkout_id = body.get('CheckoutRequestID') or callback_data.get('CheckoutRequestID')
    result_code = body.get('ResultCode', -1)
    result_desc = body.get('ResultDesc', '')

    callback_metadata = body.get('CallbackMetadata', {}).get('Item', [])
    mpesa_receipt = next(
        (item.get('Value') for item in callback_metadata if item.get('Name') == 'MpesaReceiptNumber'),
        None,
    )

    try:
        payment = Payment.objects.get(mpesa_checkout_request_id=checkout_id)
    except Payment.DoesNotExist:
        return {'status': 'error', 'reason': 'payment not found'}

    if result_code == 0:
        payment.status = 'completed'
        payment.mpesa_receipt_number = mpesa_receipt or ''
        payment.paid_at = timezone.now()
        payment.provider_response = callback_data
        payment.save(update_fields=['status', 'mpesa_receipt_number', 'paid_at', 'provider_response'])

        # Mark invoice paid
        if hasattr(payment, 'invoice') and payment.invoice:
            inv = payment.invoice
            inv.amount_paid = (inv.amount_paid or 0) + payment.amount
            inv.amount_due = max(0, (inv.total or 0) - inv.amount_paid)
            if inv.amount_due == 0:
                inv.status = 'paid'
                inv.paid_at = timezone.now()
            inv.save(update_fields=['amount_paid', 'amount_due', 'status', 'paid_at'])

            # Activate subscription
            if hasattr(inv, 'subscription') and inv.subscription:
                inv.subscription.status = 'active'
                inv.subscription.save(update_fields=['status'])
    else:
        payment.status = 'failed'
        payment.failure_reason = result_desc
        payment.failed_at = timezone.now()
        payment.provider_response = callback_data
        payment.save(update_fields=['status', 'failure_reason', 'failed_at', 'provider_response'])

    return {'status': 'processed', 'payment_status': payment.status}


@shared_task
def generate_invoices():
    from apps.billing.models import Plan, Subscription, Invoice

    due = Subscription.objects.filter(
        status='active',
        current_period_end__lte=timezone.now() + timezone.timedelta(days=3),
        cancel_at_period_end=False,
    )

    created = 0
    for sub in due:
        if Invoice.objects.filter(subscription=sub, period_end=sub.current_period_end).exists():
            continue

        plan = sub.plan
        base_amount = (
            plan.monthly_price_kes
            if sub.billing_cycle == 'monthly'
            else plan.yearly_price_kes
        )
        discount = getattr(sub, 'discount_percent', 0) or 0
        amount = float(base_amount) * (1 - discount / 100)
        tax_rate = float(getattr(settings, 'TAX_RATE', 0.16))
        tax = amount * tax_rate
        total = amount + tax

        import uuid as _uuid
        invoice_number = f'INV-{timezone.now().strftime("%Y%m")}-{str(_uuid.uuid4())[:8].upper()}'

        Invoice.objects.create(
            organization=sub.organization,
            subscription=sub,
            invoice_number=invoice_number,
            status='open',
            subtotal=amount,
            tax_amount=tax,
            total=total,
            amount_due=total,
            period_start=sub.current_period_start,
            period_end=sub.current_period_end,
            due_date=timezone.now() + timezone.timedelta(days=14),
            line_items=[{
                'description': f'{plan.name} Subscription ({sub.billing_cycle})',
                'quantity': getattr(sub, 'quantity', 1),
                'unit_price': amount,
                'total': amount,
            }],
        )
        created += 1

    return f'Created {created} invoices'


@shared_task
def process_recurring_payments():
    from apps.billing.models import Invoice, Payment

    pending = Invoice.objects.filter(
        status='open',
        due_date__lte=timezone.now(),
        amount_due__gt=0,
    )

    count = 0
    for invoice in pending:
        sub = getattr(invoice, 'subscription', None)
        if not sub or sub.plan.tier == 'free':
            continue
        payment = Payment.objects.create(
            organization=invoice.organization,
            invoice=invoice,
            amount=invoice.amount_due,
            currency=getattr(invoice, 'currency', 'KES'),
            status='pending',
            provider='mpesa',
        )
        process_mpesa_payment.delay(str(payment.id))
        count += 1

    return f'Processed {count} invoices'


@shared_task
def send_payment_reminders():
    from apps.billing.models import Invoice
    from django.core.mail import send_mail

    overdue = Invoice.objects.filter(
        status='open',
        due_date__lt=timezone.now(),
        amount_due__gt=0,
    )

    sent = 0
    for invoice in overdue:
        days_overdue = (timezone.now() - invoice.due_date).days

        try:
            # Try to get a contact email — fall back gracefully
            org = invoice.organization
            to_email = None
            if hasattr(org, 'billing_email') and org.billing_email:
                to_email = org.billing_email
            elif hasattr(org, 'owner') and org.owner:
                to_email = org.owner.email

            if not to_email:
                continue

            subject = (
                f'TrustScan: Invoice {invoice.invoice_number} '
                f'is {days_overdue} day{"s" if days_overdue != 1 else ""} overdue'
            )
            message = (
                f'Dear {org.name},\n\n'
                f'Invoice {invoice.invoice_number} for KES {float(invoice.amount_due):,.2f} '
                f'is {days_overdue} day{"s" if days_overdue != 1 else ""} overdue.\n\n'
                f'Please make payment to avoid service interruption.\n\n'
                f'View invoice: {getattr(settings, "FRONTEND_URL", "https://trustscan.co.ke")}/invoices/{invoice.id}\n\n'
                f'Regards,\nTrustScan Team'
            )
            send_mail(
                subject,
                message,
                settings.DEFAULT_FROM_EMAIL,
                [to_email],
                fail_silently=False,
            )
            sent += 1
        except Exception:
            pass

    return f'Sent {sent} payment reminders'


@shared_task
def update_usage_records():
    from apps.billing.models import Subscription, UsageRecord
    from apps.scanner.models import ScanJob
    from apps.domains.models import Domain

    subscriptions = Subscription.objects.filter(status__in=['active', 'trial'])

    for sub in subscriptions:
        domains_count = Domain.objects.filter(
            organization=sub.organization, deleted_at__isnull=True
        ).count()
        scans_performed = ScanJob.objects.filter(
            domain__organization=sub.organization,
            status='completed',
            completed_at__gte=sub.current_period_start,
            completed_at__lt=sub.current_period_end,
        ).count()

        UsageRecord.objects.update_or_create(
            subscription=sub,
            period_start=sub.current_period_start,
            defaults={
                'period_end': sub.current_period_end,
                'domains_count': domains_count,
                'scans_performed': scans_performed,
                'organization': sub.organization,
            },
        )

    return f'Updated {subscriptions.count()} usage records'


@shared_task
def check_subscription_limits():
    from apps.billing.models import Subscription
    from apps.domains.models import Domain
    from apps.scanner.models import ScanJob

    alerts = []
    for sub in Subscription.objects.filter(status='active'):
        plan = sub.plan

        # Domain limit check
        domains = Domain.objects.filter(organization=sub.organization, deleted_at__isnull=True).count()
        limit = getattr(plan, 'domains_limit', 0)
        if limit > 0 and domains >= limit * 0.9:
            alerts.append({
                'type': 'domain_limit',
                'organization': str(sub.organization.id),
                'current': domains,
                'limit': limit,
                'percentage': round(domains / limit * 100, 1),
            })

        # Scan limit check
        scan_limit = getattr(plan, 'scans_per_month', 0)
        if scan_limit > 0:
            scans = ScanJob.objects.filter(
                domain__organization=sub.organization,
                status='completed',
                completed_at__gte=sub.current_period_start,
                completed_at__lt=sub.current_period_end,
            ).count()
            if scans >= scan_limit * 0.9:
                alerts.append({
                    'type': 'scan_limit',
                    'organization': str(sub.organization.id),
                    'current': scans,
                    'limit': scan_limit,
                    'percentage': round(scans / scan_limit * 100, 1),
                })

    return {'alerts': alerts, 'count': len(alerts)}


@shared_task
def handle_failed_payments():
    from apps.billing.models import Payment, Subscription

    failed = Payment.objects.filter(
        status='failed',
        created_at__gte=timezone.now() - timezone.timedelta(days=7),
    )

    updated = 0
    for payment in failed:
        inv = getattr(payment, 'invoice', None)
        if inv and hasattr(inv, 'subscription') and inv.subscription:
            sub = inv.subscription
            if sub.status == 'active':
                sub.status = 'past_due'
                sub.save(update_fields=['status'])
                updated += 1

    return f'Marked {updated} subscriptions as past_due'
