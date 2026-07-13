from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.billing.models import Plan, Subscription, Invoice, Payment, UsageRecord, DiscountCode, CreditNote


class PlanSerializer(ModelSerializer):
    class Meta:
        model = Plan
        fields = '__all__'


class SubscriptionSerializer(ModelSerializer):
    class Meta:
        model = Subscription
        fields = '__all__'


class InvoiceSerializer(ModelSerializer):
    class Meta:
        model = Invoice
        fields = '__all__'


class PaymentSerializer(ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'


class UsageRecordSerializer(ModelSerializer):
    class Meta:
        model = UsageRecord
        fields = '__all__'


class DiscountCodeSerializer(ModelSerializer):
    class Meta:
        model = DiscountCode
        fields = '__all__'


class CreditNoteSerializer(ModelSerializer):
    class Meta:
        model = CreditNote
        fields = '__all__'


class PlanViewSet(viewsets.ModelViewSet):
    queryset = Plan.objects.all()
    serializer_class = PlanSerializer
    permission_classes = [AllowAny]


class SubscriptionViewSet(viewsets.ModelViewSet):
    queryset = Subscription.objects.all().select_related('organization', 'plan')
    serializer_class = SubscriptionSerializer
    permission_classes = [AllowAny]


class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all().select_related('organization', 'subscription')
    serializer_class = InvoiceSerializer
    permission_classes = [AllowAny]


class PaymentViewSet(viewsets.ModelViewSet):
    queryset = Payment.objects.all().select_related('organization', 'invoice')
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]


class UsageRecordViewSet(viewsets.ModelViewSet):
    queryset = UsageRecord.objects.all().select_related('organization')
    serializer_class = UsageRecordSerializer
    permission_classes = [AllowAny]


class DiscountCodeViewSet(viewsets.ModelViewSet):
    queryset = DiscountCode.objects.all()
    serializer_class = DiscountCodeSerializer
    permission_classes = [AllowAny]


class CreditNoteViewSet(viewsets.ModelViewSet):
    queryset = CreditNote.objects.all().select_related('organization', 'invoice')
    serializer_class = CreditNoteSerializer
    permission_classes = [AllowAny]
