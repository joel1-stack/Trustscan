from drf_spectacular.utils import extend_schema, OpenApiParameter, OpenApiExample
from drf_spectacular.openapi import OpenApiSchemaGenerator


class TrustScanSchemaGenerator(OpenApiSchemaGenerator):
    def get_schema(self, request=None, public=False):
        schema = super().get_schema(request, public)
        schema.info.title = 'TrustScan API'
        schema.info.description = 'Digital Trust Intelligence Platform API - Map and protect your digital business'
        schema.info.version = '1.0.0'
        schema.info.contact = {'name': 'TrustScan Support', 'email': 'support@trustscan.co.ke', 'url': 'https://trustscan.co.ke'}
        schema.info.license = {'name': 'Proprietary', 'url': 'https://trustscan.co.ke/license'}
        return schema


TRUSTSCAN_TAGS = [
    {'name': 'Domains', 'description': 'Domain management and portfolio operations'},
    {'name': 'Scanning', 'description': 'Digital trust scanning operations'},
    {'name': 'Reports', 'description': 'Trust report generation and delivery'},
    {'name': 'Billing', 'description': 'Subscription and billing management'},
    {'name': 'Webhooks', 'description': 'Webhook configuration and management'},
    {'name': 'API Keys', 'description': 'API key management for integrations'},
    {'name': 'Organizations', 'description': 'Organization and team management'},
    {'name': 'Authentication', 'description': 'User authentication and authorization'},
]

SPECTACULAR_SETTINGS = {
    'TITLE': 'TrustScan API',
    'DESCRIPTION': 'Digital Trust Intelligence Platform API - Map and protect your digital business',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'SCHEMA_PATH_PREFIX': '/api/v1',
    'SORT_OPERATIONS': True,
    'SORT_OPERATION_PARAMETERS': True,
    'TAGS': TRUSTSCAN_TAGS,
    'EXTERNAL_DOCS': {
        'description': 'TrustScan Documentation',
        'url': 'https://docs.trustscan.co.ke',
    },
    'CONTACT': {
        'name': 'TrustScan Support',
        'email': 'support@trustscan.co.ke',
        'url': 'https://trustscan.co.ke',
    },
    'LICENSE': {
        'name': 'Proprietary',
        'url': 'https://trustscan.co.ke/license',
    },
    'SERVERS': [
        {'url': 'https://api.trustscan.co.ke/v1', 'description': 'Production server'},
        {'url': 'https://staging-api.trustscan.co.ke/v1', 'description': 'Staging server'},
        {'url': 'http://localhost:8000/api/v1', 'description': 'Development server'},
    ],
    'SECURITY': [
        {'ApiKeyAuth': []},
        {'BearerAuth': []},
    ],
    'COMPONENTS': {
        'securitySchemes': {
            'ApiKeyAuth': {
                'type': 'apiKey',
                'in': 'header',
                'name': 'Authorization',
                'description': 'API Key authentication. Format: Bearer ts_<prefix>_<key>',
            },
            'BearerAuth': {
                'type': 'http',
                'scheme': 'bearer',
                'bearerFormat': 'JWT',
                'description': 'JWT token authentication for user sessions',
            },
        },
    },
    'POSTPROCESSING_HOOKS': [
        'apps.api.documentation.postprocess_schema',
    ],
}

OPENAPI_EXAMPLES = {
    'ScanJob': {
        'value': {
            'scan_id': '550e8400-e29b-41d4-a716-446655440000',
            'status': 'started',
            'domain': 'example.co.ke',
            'estimated_duration_seconds': 120,
        }
    },
    'TrustScore': {
        'value': {
            'overall': 86,
            'status': 'good',
            'confidence': 92,
            'dimensions': {
                'email_security': 90,
                'infrastructure_hygiene': 85,
                'exposure_surface': 80,
                'breach_history': 95,
                'reputation_trust': 78,
                'identity_integrity': 88,
            },
        }
    },
    'Domain': {
        'value': {
            'id': '550e8400-e29b-41d4-a716-446655440000',
            'name': 'example.co.ke',
            'root_domain': 'example.co.ke',
            'tld': 'co.ke',
            'industry': 'financial_services',
            'is_verified': True,
            'current_trust_score': 86,
            'current_score_status': 'good',
            'last_scanned_at': '2024-01-15T10:30:00Z',
            'is_monitored': True,
        }
    },
    'Error': {
        'value': {
            'error': {
                'code': 'validation_error',
                'message': 'Invalid input data.',
                'details': {
                    'domain': ['Enter a valid domain name.']
                }
            }
        }
    },
}

EXTENDED_SCHEMA_OVERRIDES = {
    'trust_score': extend_schema(
        parameters=[
            OpenApiParameter(
                name='domain',
                type=str,
                location=OpenApiParameter.PATH,
                description='Domain to get trust score for',
                required=True,
            ),
        ],
        responses={
            200: {
                'type': 'object',
                'properties': {
                    'domain': {'type': 'string'},
                    'scan_id': {'type': 'string'},
                    'status': {'type': 'string'},
                    'trust_score': {'type': 'object'},
                    'critical_findings': {'type': 'integer'},
                    'high_findings': {'type': 'integer'},
                    'correlations': {'type': 'array'},
                    'recommendations': {'type': 'array'},
                    'benchmarks': {'type': 'object'},
                }
            }
        },
        examples=[
            OpenApiExample(
                'Success Response',
                value={
                    'domain': 'hospital.co.ke',
                    'scan_id': '550e8400-e29b-41d4-a716-446655440000',
                    'status': 'COMPLETED',
                    'trust_score': {
                        'overall': 62,
                        'dimensions': {
                            'email_security': 45,
                            'infrastructure_hygiene': 70,
                            'exposure_surface': 55,
                            'breach_history': 80,
                            'reputation': 60,
                            'identity_integrity': 50
                        }
                    },
                    'critical_findings': 3,
                    'high_findings': 5,
                    'correlations': ['CORR-001', 'CORR-007'],
                    'recommendations': [
                        {
                            'priority': 1,
                            'action': 'Add DMARC record with p=reject',
                            'impact': '+15 points',
                            'effort': 'Low'
                        }
                    ],
                    'benchmarks': {
                        'industry_average': 58,
                        'percentile': 65
                    }
                }
            ),
            OpenApiExample(
                'Unauthorized',
                value={
                    'error': {
                        'code': 'unauthorized',
                        'message': 'API key is required',
                        'details': {}
                    }
                },
                status_codes=['401']
            ),
        ]
    ),
}

API_REFERENCE_MARKDOWN = '''
# TrustScan API Reference

## Authentication

All API requests require authentication via API Key:

```
Authorization: Bearer ts_<prefix>_<key>
```

API keys can be created in the TrustScan dashboard under **Settings > API Keys**.

## Rate Limits

Rate limits are based on your subscription tier:

| Tier | Requests/Hour | Scans/Day |
|------|---------------|-----------|
| Free | 100 | 1 |
| Business | 1,000 | 7 |
| Pro | 5,000 | 30 |
| Enterprise | 20,000 | 1,000 |

Rate limit headers are included in all responses:
- `X-RateLimit-Limit`: Request limit
- `X-RateLimit-Remaining`: Requests remaining
- `X-RateLimit-Reset`: Unix timestamp when limit resets

## Error Format

All errors follow a consistent format:

```json
{
  "error": {
    "code": "error_code",
    "message": "Human readable message",
    "details": {}
  }
}
```

Common error codes:
- `unauthorized` - Invalid or missing API key
- `forbidden` - Insufficient permissions
- `rate_limit` - Rate limit exceeded
- `validation_error` - Invalid input data
- `not_found` - Resource not found
- `internal_error` - Server error

## Versioning

API version is included in the URL path: `/api/v1/`

## Webhooks

Configure webhooks to receive real-time events:

Events:
- `scan.completed` - Scan finished
- `scan.failed` - Scan failed
- `score.changed` - Trust score changed
- `report.generated` - Report ready
- `alert.triggered` - Alert condition met

Webhook payload is signed with HMAC-SHA256 using your webhook secret.
'''