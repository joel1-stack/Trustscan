from rest_framework import filters, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.discovery.models import DiscoveryMap, Asset, DNSRecord, CertificateEntry, WhoisRecord


class DiscoveryMapSerializer(ModelSerializer):
    class Meta:
        model = DiscoveryMap
        fields = '__all__'


class AssetSerializer(ModelSerializer):
    class Meta:
        model = Asset
        fields = '__all__'


class DNSRecordSerializer(ModelSerializer):
    class Meta:
        model = DNSRecord
        fields = '__all__'


class CertificateEntrySerializer(ModelSerializer):
    class Meta:
        model = CertificateEntry
        fields = '__all__'


class WhoisRecordSerializer(ModelSerializer):
    class Meta:
        model = WhoisRecord
        fields = '__all__'


class DiscoveryMapViewSet(viewsets.ModelViewSet):
    queryset = DiscoveryMap.objects.all()
    serializer_class = DiscoveryMapSerializer
    permission_classes = [AllowAny]


class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all().select_related('domain')
    serializer_class = AssetSerializer
    permission_classes = [AllowAny]


class DNSRecordViewSet(viewsets.ModelViewSet):
    queryset = DNSRecord.objects.all().select_related('asset')
    serializer_class = DNSRecordSerializer
    permission_classes = [AllowAny]


class CertificateEntryViewSet(viewsets.ModelViewSet):
    queryset = CertificateEntry.objects.all().select_related('asset')
    serializer_class = CertificateEntrySerializer
    permission_classes = [AllowAny]


class WhoisRecordViewSet(viewsets.ModelViewSet):
    queryset = WhoisRecord.objects.all().select_related('asset')
    serializer_class = WhoisRecordSerializer
    permission_classes = [AllowAny]
