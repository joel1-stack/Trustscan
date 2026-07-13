from rest_framework import serializers
from apps.api.models import (
    PublicAPIKey, WebhookEndpoint, WebhookDelivery, APIRequestLog, APIUsageQuota
)


class PublicAPIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model = PublicAPIKey
        fields = [
            'id', 'name', 'key_prefix', 'scopes', 'rate_limit',
            'rate_limit_window', 'last_used_at', 'last_used_ip',
            'expires_at', 'is_active', 'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'key_prefix', 'last_used_at', 'last_used_ip',
            'created_at', 'updated_at',
        ]


class WebhookEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookEndpoint
        fields = [
            'id', 'name', 'url', 'events', 'is_active',
            'last_triggered_at', 'failure_count', 'last_failure',
            'created_at', 'updated_at',
        ]
        read_only_fields = [
            'id', 'last_triggered_at', 'failure_count', 'last_failure',
            'created_at', 'updated_at',
        ]


class WebhookDeliverySerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookDelivery
        fields = [
            'id', 'event_type', 'status', 'response_code',
            'response_body', 'error_message', 'attempts',
            'next_retry', 'delivered_at', 'created_at',
        ]
        read_only_fields = fields


class APIRequestLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = APIRequestLog
        fields = [
            'id', 'method', 'path', 'query_params', 'response_status',
            'duration_ms', 'ip_address', 'timestamp',
        ]
        read_only_fields = fields


class APIUsageQuotaSerializer(serializers.ModelSerializer):
    class Meta:
        model = APIUsageQuota
        fields = [
            'id', 'period_start', 'period_end', 'requests_count',
            'requests_limit', 'scan_requests', 'scan_limit',
            'report_requests', 'report_limit', 'created_at',
        ]
        read_only_fields = fields


class DomainSerializer(serializers.ModelSerializer):
    class Meta:
        model = 'domains.Domain'
        fields = [
            'id', 'name', 'root_domain', 'tld', 'industry',
            'is_verified', 'current_trust_score', 'current_score_status',
            'last_scanned_at', 'is_monitored',
        ]
        read_only_fields = fields


class ScanJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = 'scanner.ScanJob'
        fields = [
            'id', 'domain', 'scan_type', 'trigger_source', 'status',
            'current_phase', 'phase_progress', 'started_at',
            'completed_at', 'duration_seconds', 'trust_score',
            'score_status', 'dimension_scores', 'reports_generated',
            'created_at', 'updated_at',
        ]
        read_only_fields = fields


class TrustScoreSerializer(serializers.ModelSerializer):
    class Meta:
        model = 'scoring.TrustScore'
        fields = [
            'id', 'overall', 'status', 'confidence',
            'dimensions', 'scoring_version',
            'critical_count', 'high_count', 'medium_count',
            'low_count', 'info_count', 'correlation_count',
            'top_risks', 'top_actions', 'calculated_at',
        ]
        read_only_fields = fields