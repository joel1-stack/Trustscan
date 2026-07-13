"""
Billing app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.billing.views import (
    PlanViewSet, SubscriptionViewSet, InvoiceViewSet,
    PaymentViewSet, UsageRecordViewSet, DiscountCodeViewSet, CreditNoteViewSet
)

router = DefaultRouter()
router.register(r'plans', PlanViewSet, basename='plan')
router.register(r'subscriptions', SubscriptionViewSet, basename='subscription')
router.register(r'invoices', InvoiceViewSet, basename='invoice')
router.register(r'payments', PaymentViewSet, basename='payment')
router.register(r'usage', UsageRecordViewSet, basename='usagerecord')
router.register(r'discounts', DiscountCodeViewSet, basename='discountcode')
router.register(r'credits', CreditNoteViewSet, basename='creditnote')

urlpatterns = [
    path('', include(router.urls)),
]