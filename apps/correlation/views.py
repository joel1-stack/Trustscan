from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.correlation.models import Correlation, CorrelationRule, PatternMatch


class CorrelationSerializer(ModelSerializer):
    class Meta:
        model = Correlation
        fields = '__all__'


class CorrelationRuleSerializer(ModelSerializer):
    class Meta:
        model = CorrelationRule
        fields = '__all__'


class PatternMatchSerializer(ModelSerializer):
    class Meta:
        model = PatternMatch
        fields = '__all__'


class CorrelationViewSet(viewsets.ModelViewSet):
    queryset = Correlation.objects.all().select_related('scan_job')
    serializer_class = CorrelationSerializer
    permission_classes = [AllowAny]


class CorrelationRuleViewSet(viewsets.ModelViewSet):
    queryset = CorrelationRule.objects.all()
    serializer_class = CorrelationRuleSerializer
    permission_classes = [AllowAny]


class PatternMatchViewSet(viewsets.ModelViewSet):
    queryset = PatternMatch.objects.all().select_related('scan_job', 'rule')
    serializer_class = PatternMatchSerializer
    permission_classes = [AllowAny]
