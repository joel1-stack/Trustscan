from rest_framework.throttling import UserRateThrottle
from django.core.cache import cache
from apps.api.models import APIUsageQuota


class TieredRateThrottle:
    RATE_LIMITS = {
        'free': '100/hour',
        'business': '1000/hour',
        'pro': '5000/hour',
        'enterprise': '20000/hour',
    }
    
    def get_rate(self, request):
        if not hasattr(request, 'auth') or not request.auth:
            return '100/hour'
        
        plan = getattr(request.auth.organization, 'subscription', None)
        if plan:
            return self.RATE_LIMITS.get(plan.plan.tier, '1000/hour')
        return '100/hour'


class APIKeyRateThrottle(UserRateThrottle):
    def get_cache_key(self, request, view):
        if not hasattr(request, 'auth') or not request.auth:
            return None
        
        ident = request.auth.key_prefix
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
    
    def get_rate(self):
        if not hasattr(self.request, 'auth') or not self.request.auth:
            return '100/hour'
        
        return self.request.auth.rate_limit or '100/hour'


class OrganizationRateThrottle(UserRateThrottle):
    def get_cache_key(self, request, view):
        if not hasattr(request, 'auth') or not request.auth:
            return None
        
        ident = str(request.auth.organization.id)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
    
    def get_rate(self):
        if not hasattr(self.request, 'auth') or not self.request.auth:
            return '100/hour'
        
        org = self.request.auth.organization
        subscription = getattr(org, 'subscription', None)
        
        if subscription:
            tier = subscription.plan.tier
            if tier == 'free':
                return '100/hour'
            elif tier == 'business':
                return '1000/hour'
            elif tier == 'pro':
                return '5000/hour'
            elif tier == 'enterprise':
                return '20000/hour'
        
        return '100/hour'


class ScanThrottle(UserRateThrottle):
    scope = 'scan'
    rate = '10/day'
    
    def get_cache_key(self, request, view):
        if not hasattr(request, 'auth') or not request.auth:
            return None
        
        ident = f"scan:{request.auth.organization.id}"
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
    
    def get_rate(self):
        if not hasattr(self.request, 'auth') or not self.request.auth:
            return '1/day'
        
        org = self.request.auth.organization
        subscription = getattr(org, 'subscription', None)
        
        if subscription:
            tier = subscription.plan.tier
            if tier == 'free':
                return '1/day'
            elif tier == 'business':
                return '7/day'
            elif tier == 'pro':
                return '30/day'
            elif tier == 'enterprise':
                return '1000/day'
        
        return '1/day'


class ReportThrottle(UserRateThrottle):
    scope = 'report'
    rate = '50/hour'
    
    def get_cache_key(self, request, view):
        if not hasattr(request, 'auth') or not request.auth:
            return None
        
        ident = f"report:{request.auth.organization.id}"
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class WebhookThrottle(UserRateThrottle):
    scope = 'webhook'
    rate = '100/minute'
    
    def get_cache_key(self, request, view):
        if not hasattr(request, 'auth') or not request.auth:
            return None
        
        ident = f"webhook:{request.auth.organization.id}"
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }


class AnonymousThrottle(UserRateThrottle):
    scope = 'anonymous'
    rate = '20/hour'
    
    def get_cache_key(self, request, view):
        ip = self.get_ident(request)
        return self.cache_format % {
            'scope': self.scope,
            'ident': ip
        }
    
    def get_ident(self, request):
        xff = request.META.get('HTTP_X_FORWARDED_FOR')
        if xff:
            return xff.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', 'unknown')


class BurstThrottle(UserRateThrottle):
    scope = 'burst'
    rate = '10/second'
    
    def get_cache_key(self, request, view):
        if hasattr(request, 'auth') and request.auth:
            ident = f"burst:{request.auth.organization.id}"
        else:
            ident = f"burst:anon:{self.get_ident(request)}"
        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }