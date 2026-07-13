from django.core.exceptions import ValidationError


class TrustScanException(Exception):
    default_message = 'An error occurred in TrustScan.'
    default_code = 'trustscan_error'

    def __init__(self, message=None, code=None, details=None):
        self.message = message or self.default_message
        self.code = code or self.default_code
        self.details = details or {}
        super().__init__(self.message)


class AuthorizationError(TrustScanException):
    default_message = 'Domain not authorized for scanning.'
    default_code = 'authorization_error'


class VerificationError(TrustScanException):
    default_message = 'Domain verification failed.'
    default_code = 'verification_error'


class ScanError(TrustScanException):
    default_message = 'Scan execution failed.'
    default_code = 'scan_error'


class RateLimitError(TrustScanException):
    default_message = 'Rate limit exceeded. Please try again later.'
    default_code = 'rate_limit_error'


class ExternalAPIError(TrustScanException):
    default_message = 'External API request failed.'
    default_code = 'external_api_error'


class ScoringError(TrustScanException):
    default_message = 'Trust score calculation failed.'
    default_code = 'scoring_error'


class ReportGenerationError(TrustScanException):
    default_message = 'Report generation failed.'
    default_code = 'report_generation_error'


class BillingError(TrustScanException):
    default_message = 'Billing operation failed.'
    default_code = 'billing_error'


class ConfigurationError(TrustScanException):
    default_message = 'System configuration error.'
    default_code = 'configuration_error'


class DomainBlockedError(TrustScanException):
    default_message = 'This domain is blocked from scanning.'
    default_code = 'domain_blocked_error'


class VerificationTokenExpiredError(TrustScanException):
    default_message = 'Verification token has expired.'
    default_code = 'verification_token_expired'


class VerificationTokenInvalidError(TrustScanException):
    default_message = 'Verification token is invalid.'
    default_code = 'verification_token_invalid'


class ScanJobNotFoundError(TrustScanException):
    default_message = 'Scan job not found.'
    default_code = 'scan_job_not_found'


class InsufficientPermissionsError(TrustScanException):
    default_message = 'Insufficient permissions to perform this action.'
    default_code = 'insufficient_permissions'


class DomainNotFoundError(TrustScanException):
    default_message = 'Domain not found in your portfolio.'
    default_code = 'domain_not_found'


class SubscriptionRequiredError(TrustScanException):
    default_message = 'This feature requires an active subscription.'
    default_code = 'subscription_required'


class QuotaExceededError(TrustScanException):
    default_message = 'Scan quota exceeded for your current plan.'
    default_code = 'quota_exceeded'


def custom_exception_handler(exc, context):
    from rest_framework.views import exception_handler
    from rest_framework.response import Response
    from rest_framework import status

    response = exception_handler(exc, context)

    if isinstance(exc, TrustScanException):
        return Response(
            {
                'error': {
                    'code': exc.code,
                    'message': exc.message,
                    'details': exc.details,
                }
            },
            status=status.HTTP_400_BAD_REQUEST
        )

    if response is not None:
        custom_data = {
            'error': {
                'code': 'validation_error',
                'message': 'Invalid input data.',
                'details': response.data,
            }
        }
        response.data = custom_data

    return response