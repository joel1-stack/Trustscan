import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from apps.core.models import UUIDTimestampedModel, SoftDeleteModel


class User(AbstractUser, UUIDTimestampedModel):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(_('email address'), unique=True)
    phone_number = models.CharField(_('phone number'), max_length=20, blank=True)
    is_verified = models.BooleanField(_('verified'), default=False)
    last_login_ip = models.GenericIPAddressField(_('last login IP'), null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    timezone = models.CharField(_('timezone'), max_length=50, default='Africa/Nairobi')
    language = models.CharField(_('language'), max_length=10, default='en')
    marketing_consent = models.BooleanField(default=False)
    terms_accepted_at = models.DateTimeField(null=True, blank=True)
    terms_version = models.CharField(max_length=20, blank=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    class Meta:
        db_table = 'accounts_user'
        verbose_name = _('User')
        verbose_name_plural = _('Users')
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.email


class Organization(UUIDTimestampedModel, SoftDeleteModel):
    name = models.CharField(_('name'), max_length=255)
    slug = models.SlugField(_('slug'), max_length=100, unique=True)
    description = models.TextField(_('description'), blank=True)
    website = models.URLField(_('website'), blank=True)
    industry = models.CharField(_('industry'), max_length=50, blank=True)
    country = models.CharField(_('country'), max_length=2, default='KE')
    city = models.CharField(_('city'), max_length=100, blank=True)
    logo = models.ImageField(_('logo'), upload_to='organizations/logos/', null=True, blank=True)
    primary_color = models.CharField(_('primary color'), max_length=7, default='#1E40AF')
    settings = models.JSONField(_('settings'), default=dict, blank=True)
    is_active = models.BooleanField(_('active'), default=True)
    trial_ends_at = models.DateTimeField(_('trial ends at'), null=True, blank=True)

    class Meta:
        db_table = 'accounts_organization'
        verbose_name = _('Organization')
        verbose_name_plural = _('Organizations')
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class Team(UUIDTimestampedModel, SoftDeleteModel):
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='teams'
    )
    name = models.CharField(_('name'), max_length=100)
    description = models.TextField(_('description'), blank=True)
    is_default = models.BooleanField(_('default'), default=False)

    class Meta:
        db_table = 'accounts_team'
        verbose_name = _('Team')
        verbose_name_plural = _('Teams')
        unique_together = ['organization', 'name']
        ordering = ['name']

    def __str__(self):
        return f"{self.organization.name} - {self.name}"


class Membership(UUIDTimestampedModel):
    ROLE_OWNER = 'owner'
    ROLE_ADMIN = 'admin'
    ROLE_MEMBER = 'member'
    ROLE_VIEWER = 'viewer'

    ROLE_CHOICES = [
        (ROLE_OWNER, _('Owner')),
        (ROLE_ADMIN, _('Admin')),
        (ROLE_MEMBER, _('Member')),
        (ROLE_VIEWER, _('Viewer')),
    ]

    PERMISSIONS = {
        ROLE_OWNER: ['*'],
        ROLE_ADMIN: [
            'manage_organization', 'manage_domains', 'manage_scans',
            'view_reports', 'manage_billing', 'manage_team', 'manage_integrations'
        ],
        ROLE_MEMBER: [
            'manage_domains', 'manage_scans', 'view_reports'
        ],
        ROLE_VIEWER: [
            'view_reports'
        ],
    }

    user = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='memberships'
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='memberships'
    )
    team = models.ForeignKey(
        Team,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='memberships'
    )
    role = models.CharField(_('role'), max_length=20, choices=ROLE_CHOICES, default=ROLE_MEMBER)
    is_active = models.BooleanField(_('active'), default=True)
    invited_by = models.ForeignKey(
        'User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='invitations_sent'
    )
    invited_at = models.DateTimeField(_('invited at'), auto_now_add=True)
    joined_at = models.DateTimeField(_('joined at'), null=True, blank=True)

    class Meta:
        db_table = 'accounts_membership'
        verbose_name = _('Membership')
        verbose_name_plural = _('Memberships')
        unique_together = ['user', 'organization']
        indexes = [
            models.Index(fields=['user', 'organization']),
            models.Index(fields=['organization', 'is_active']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.organization.name} ({self.role})"

    def has_permission(self, permission):
        role_perms = self.PERMISSIONS.get(self.role, [])
        return '*' in role_perms or permission in role_perms


class Invitation(UUIDTimestampedModel):
    STATUS_PENDING = 'pending'
    STATUS_ACCEPTED = 'accepted'
    STATUS_DECLINED = 'declined'
    STATUS_EXPIRED = 'expired'
    STATUS_CANCELLED = 'cancelled'

    STATUS_CHOICES = [
        (STATUS_PENDING, _('Pending')),
        (STATUS_ACCEPTED, _('Accepted')),
        (STATUS_DECLINED, _('Declined')),
        (STATUS_EXPIRED, _('Expired')),
        (STATUS_CANCELLED, _('Cancelled')),
    ]

    email = models.EmailField(_('email'))
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='invitations'
    )
    team = models.ForeignKey(
        Team,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='invitations'
    )
    role = models.CharField(_('role'), max_length=20, choices=Membership.ROLE_CHOICES, default=Membership.ROLE_MEMBER)
    invited_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='invitations_created'
    )
    token = models.CharField(_('token'), max_length=64, unique=True)
    status = models.CharField(_('status'), max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    expires_at = models.DateTimeField(_('expires at'))
    accepted_at = models.DateTimeField(_('accepted at'), null=True, blank=True)

    class Meta:
        db_table = 'accounts_invitation'
        verbose_name = _('Invitation')
        verbose_name_plural = _('Invitations')
        indexes = [
            models.Index(fields=['token']),
            models.Index(fields=['email', 'organization']),
        ]

    def is_valid(self):
        return self.status == self.STATUS_PENDING and self.expires_at > timezone.now()

    def __str__(self):
        return f"Invitation for {self.email} to {self.organization.name}"


class UserAPIKey(UUIDTimestampedModel, SoftDeleteModel):
    name = models.CharField(_('name'), max_length=100)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='user_api_keys'
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='user_api_keys_created'
    )
    key_hash = models.CharField(_('key hash'), max_length=64)
    key_prefix = models.CharField(_('key prefix'), max_length=8)
    scopes = models.JSONField(_('scopes'), default=list)
    last_used_at = models.DateTimeField(_('last used at'), null=True, blank=True)
    expires_at = models.DateTimeField(_('expires at'), null=True, blank=True)
    is_active = models.BooleanField(_('active'), default=True)
    rate_limit = models.PositiveIntegerField(_('rate limit'), default=1000)

    class Meta:
        db_table = 'accounts_user_apikey'
        verbose_name = _('User API Key')
        verbose_name_plural = _('User API Keys')
        indexes = [
            models.Index(fields=['organization', 'is_active']),
            models.Index(fields=['key_prefix']),
        ]

    def __str__(self):
        return f"{self.name} ({self.key_prefix}...)"


class AuditLog(UUIDTimestampedModel):
    ACTION_CREATE = 'create'
    ACTION_UPDATE = 'update'
    ACTION_DELETE = 'delete'
    ACTION_VIEW = 'view'
    ACTION_LOGIN = 'login'
    ACTION_LOGOUT = 'logout'
    ACTION_SCAN_START = 'scan_start'
    ACTION_SCAN_COMPLETE = 'scan_complete'
    ACTION_SCAN_FAILED = 'scan_failed'
    ACTION_VERIFICATION = 'verification'
    ACTION_AUTHORIZATION = 'authorization'
    ACTION_BILLING = 'billing'

    ACTION_CHOICES = [
        (ACTION_CREATE, _('Create')),
        (ACTION_UPDATE, _('Update')),
        (ACTION_DELETE, _('Delete')),
        (ACTION_VIEW, _('View')),
        (ACTION_LOGIN, _('Login')),
        (ACTION_LOGOUT, _('Logout')),
        (ACTION_SCAN_START, _('Scan Start')),
        (ACTION_SCAN_COMPLETE, _('Scan Complete')),
        (ACTION_SCAN_FAILED, _('Scan Failed')),
        (ACTION_VERIFICATION, _('Verification')),
        (ACTION_AUTHORIZATION, _('Authorization')),
        (ACTION_BILLING, _('Billing')),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='audit_logs'
    )
    action = models.CharField(_('action'), max_length=50, choices=ACTION_CHOICES)
    resource_type = models.CharField(_('resource type'), max_length=100)
    resource_id = models.CharField(_('resource id'), max_length=100)
    ip_address = models.GenericIPAddressField(_('IP address'), null=True, blank=True)
    user_agent = models.TextField(_('user agent'), blank=True)
    metadata = models.JSONField(_('metadata'), default=dict)
    timestamp = models.DateTimeField(_('timestamp'), auto_now_add=True, db_index=True)

    class Meta:
        db_table = 'accounts_auditlog'
        verbose_name = _('Audit Log')
        verbose_name_plural = _('Audit Logs')
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization', 'timestamp']),
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]

    def __str__(self):
        return f"{self.timestamp} - {self.user} - {self.action} - {self.resource_type}"