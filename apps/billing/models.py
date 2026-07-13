import uuid
from django.db import models
from django.utils import timezone
from django.conf import settings
from apps.core.models import UUIDTimestampedSoftDeleteModel
from apps.core.constants import (
    PlanTierChoices, BillingCycleChoices, PaymentStatusChoices
)


class Plan(UUIDTimestampedSoftDeleteModel):
    name = models.CharField(max_length=100, unique=True)
    tier = models.CharField(max_length=20, choices=PlanTierChoices.choices, unique=True)
    description = models.TextField(blank=True)
    
    monthly_price_kes = models.PositiveIntegerField(default=0)
    yearly_price_kes = models.PositiveIntegerField(default=0)
    setup_fee_kes = models.PositiveIntegerField(default=0)
    
    domains_limit = models.PositiveIntegerField(default=1)
    scans_per_month = models.PositiveIntegerField(default=1)
    scan_frequency = models.CharField(max_length=20, default='monthly')
    max_subdomains_per_scan = models.PositiveIntegerField(default=100)
    
    api_access = models.BooleanField(default=False)
    api_rate_limit = models.PositiveIntegerField(default=1000)
    pdf_reports = models.BooleanField(default=False)
    alerts = models.BooleanField(default=False)
    white_label = models.BooleanField(default=False)
    custom_rules = models.BooleanField(default=False)
    sso = models.BooleanField(default=False)
    dedicated_support = models.BooleanField(default=False)
    sla_guarantee = models.CharField(max_length=50, blank=True)
    
    features = models.JSONField(default=dict)
    is_active = models.BooleanField(default=True)
    is_public = models.BooleanField(default=True)
    sort_order = models.PositiveSmallIntegerField(default=0)
    
    stripe_price_id_monthly = models.CharField(max_length=100, blank=True)
    stripe_price_id_yearly = models.CharField(max_length=100, blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'billing_plan'
        verbose_name = 'Plan'
        verbose_name_plural = 'Plans'
        ordering = ['sort_order', 'tier']

    def __str__(self):
        return f"{self.name} ({self.tier})"


class Subscription(UUIDTimestampedSoftDeleteModel):
    STATUS_CHOICES = [
        ('trial', 'Trial'),
        ('active', 'Active'),
        ('past_due', 'Past Due'),
        ('canceled', 'Canceled'),
        ('expired', 'Expired'),
        ('paused', 'Paused'),
    ]
    
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='subscriptions'
    )
    plan = models.ForeignKey(
        Plan,
        on_delete=models.PROTECT,
        related_name='subscriptions'
    )
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='trial')
    billing_cycle = models.CharField(max_length=20, choices=BillingCycleChoices.choices, default=BillingCycleChoices.MONTHLY)
    quantity = models.PositiveIntegerField(default=1)
    discount_percent = models.DecimalField(max_digits=5, decimal_places=2, default=0)
    
    current_period_start = models.DateTimeField()
    current_period_end = models.DateTimeField()
    trial_ends_at = models.DateTimeField(null=True, blank=True)
    canceled_at = models.DateTimeField(null=True, blank=True)
    cancel_at_period_end = models.BooleanField(default=False)
    
    payment_method = models.CharField(max_length=50, blank=True)
    stripe_customer_id = models.CharField(max_length=100, blank=True)
    stripe_subscription_id = models.CharField(max_length=100, blank=True)
    
    auto_renew = models.BooleanField(default=True)
    proration_behavior = models.CharField(max_length=20, choices=[
        ('none', 'None'),
        ('create_prorations', 'Create Prorations'),
    ], default='create_prorations')
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'billing_subscription'
        verbose_name = 'Subscription'
        verbose_name_plural = 'Subscriptions'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.organization.name} - {self.plan.name} ({self.status})"

    @property
    def is_active(self):
        return self.status in ['trial', 'active'] and self.current_period_end > timezone.now()

    @property
    def days_remaining(self):
        if self.current_period_end:
            return max(0, (self.current_period_end - timezone.now()).days)
        return 0


class Invoice(UUIDTimestampedSoftDeleteModel):
    STATUS_CHOICES = [
        ('draft', 'Draft'),
        ('open', 'Open'),
        ('paid', 'Paid'),
        ('void', 'Void'),
        ('uncollectible', 'Uncollectible'),
    ]
    
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='invoices'
    )
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='invoices'
    )
    
    invoice_number = models.CharField(max_length=50, unique=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='draft')
    
    subtotal = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    tax_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    tax_rate = models.DecimalField(max_digits=5, decimal_places=4, default=0.16)
    total = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    amount_paid = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    amount_due = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    currency = models.CharField(max_length=3, default='KES')
    
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    
    issue_date = models.DateTimeField(default=timezone.now)
    due_date = models.DateTimeField()
    paid_at = models.DateTimeField(null=True, blank=True)
    
    line_items = models.JSONField(default=list)
    notes = models.TextField(blank=True)
    footer = models.TextField(blank=True)
    
    stripe_invoice_id = models.CharField(max_length=100, blank=True)
    hosted_invoice_url = models.URLField(blank=True)
    invoice_pdf = models.FileField(upload_to='invoices/%Y/%m/', null=True, blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'billing_invoice'
        verbose_name = 'Invoice'
        verbose_name_plural = 'Invoices'
        ordering = ['-issue_date']

    def __str__(self):
        return f"{self.invoice_number} - {self.organization.name} - {self.status}"


class Payment(UUIDTimestampedSoftDeleteModel):
    PROVIDER_CHOICES = [
        ('mpesa', 'M-Pesa'),
        ('stripe', 'Stripe'),
        ('bank_transfer', 'Bank Transfer'),
        ('manual', 'Manual'),
    ]
    
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='payments'
    )
    invoice = models.ForeignKey(
        Invoice,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='payments'
    )
    
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=3, default='KES')
    
    status = models.CharField(max_length=20, choices=PaymentStatusChoices.choices, default=PaymentStatusChoices.PENDING)
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES, default='mpesa')
    
    provider_transaction_id = models.CharField(max_length=100, blank=True)
    provider_reference = models.CharField(max_length=100, blank=True)
    mpesa_checkout_request_id = models.CharField(max_length=100, blank=True)
    mpesa_receipt_number = models.CharField(max_length=100, blank=True)
    
    paid_at = models.DateTimeField(null=True, blank=True)
    failed_at = models.DateTimeField(null=True, blank=True)
    failure_reason = models.TextField(blank=True)
    provider_response = models.JSONField(default=dict)
    
    refunded_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    refunded_at = models.DateTimeField(null=True, blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'billing_payment'
        verbose_name = 'Payment'
        verbose_name_plural = 'Payments'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.organization.name} - {self.amount} {self.currency} ({self.status})"


class UsageRecord(UUIDTimestampedSoftDeleteModel):
    subscription = models.ForeignKey(
        Subscription,
        on_delete=models.CASCADE,
        related_name='usage_records'
    )
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='usage_records'
    )
    
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    
    domains_count = models.PositiveIntegerField(default=0)
    scans_performed = models.PositiveIntegerField(default=0)
    api_calls = models.PositiveIntegerField(default=0)
    report_generations = models.PositiveIntegerField(default=0)
    
    overage_domains = models.PositiveIntegerField(default=0)
    overage_scans = models.PositiveIntegerField(default=0)
    overage_api_calls = models.PositiveIntegerField(default=0)
    overage_amount = models.DecimalField(max_digits=12, decimal_places=2, default=0)
    
    billed = models.BooleanField(default=False)
    billed_at = models.DateTimeField(null=True, blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'billing_usagerecord'
        verbose_name = 'Usage Record'
        verbose_name_plural = 'Usage Records'
        unique_together = [['subscription', 'period_start', 'period_end']]
        ordering = ['-period_start']

    def __str__(self):
        return f"{self.subscription} - {self.period_start.date()} to {self.period_end.date()}"


class DiscountCode(UUIDTimestampedSoftDeleteModel):
    code = models.CharField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    
    discount_type = models.CharField(max_length=20, choices=[
        ('percentage', 'Percentage'),
        ('fixed', 'Fixed Amount'),
    ])
    discount_value = models.DecimalField(max_digits=10, decimal_places=2)
    
    applies_to = models.JSONField(default=list)
    max_uses = models.PositiveIntegerField(null=True, blank=True)
    uses_count = models.PositiveIntegerField(default=0)
    
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(null=True, blank=True)
    
    is_active = models.BooleanField(default=True)
    first_payment_only = models.BooleanField(default=False)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'billing_discountcode'
        verbose_name = 'Discount Code'
        verbose_name_plural = 'Discount Codes'

    def __str__(self):
        return f"{self.code} ({self.discount_type}: {self.discount_value})"


class CreditNote(UUIDTimestampedSoftDeleteModel):
    organization = models.ForeignKey(
        'accounts.Organization',
        on_delete=models.CASCADE,
        related_name='credit_notes'
    )
    invoice = models.ForeignKey(
        Invoice,
        on_delete=models.CASCADE,
        related_name='credit_notes'
    )
    
    credit_number = models.CharField(max_length=50, unique=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    reason = models.TextField()
    
    status = models.CharField(max_length=20, choices=[
        ('draft', 'Draft'),
        ('issued', 'Issued'),
        ('applied', 'Applied'),
        ('void', 'Void'),
    ], default='draft')
    
    applied_at = models.DateTimeField(null=True, blank=True)
    
    metadata = models.JSONField(default=dict)

    class Meta:
        db_table = 'billing_creditnote'
        verbose_name = 'Credit Note'
        verbose_name_plural = 'Credit Notes'

    def __str__(self):
        return f"{self.credit_number} - {self.organization.name}"