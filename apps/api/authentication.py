import hashlib
import hmac
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from apps.api.models import PublicAPIKey


class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith('Bearer '):
            return None
        
        token = auth_header[7:].strip()
        
        if '_' not in token:
            raise AuthenticationFailed('Invalid API key format')
        
        prefix, key = token.split('_', 1)
        
        try:
            api_key = PublicAPIKey.objects.select_related('organization').get(
                key_prefix=prefix,
                is_active=True,
                is_deleted=False
            )
        except PublicAPIKey.DoesNotExist:
            raise AuthenticationFailed('Invalid API key')
        
        if api_key.expires_at and api_key.expires_at < timezone.now():
            raise AuthenticationFailed('API key has expired')
        
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        if not hmac.compare_digest(key_hash, api_key.key_hash):
            raise AuthenticationFailed('Invalid API key')
        
        api_key.last_used_at = timezone.now()
        api_key.last_used_ip = self.get_client_ip(request)
        api_key.save(update_fields=['last_used_at', 'last_used_ip'])
        
        request.auth = api_key
        return (None, api_key)
    
    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')


class APIKeyPermission:
    def has_permission(self, request, view):
        return hasattr(request, 'auth') and request.auth is not None
    
    def has_object_permission(self, request, view, obj):
        if hasattr(obj, 'organization'):
            return request.auth.organization == obj.organization
        return False


class TrustScanAPIPermission:
    def has_permission(self, request, view):
        return hasattr(request, 'auth') and request.auth is not None