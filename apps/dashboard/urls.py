"""
Dashboard app URLs.
"""
from django.urls import path
from apps.dashboard.views import AdminDashboardView

urlpatterns = [
    path('', AdminDashboardView.as_view(), name='admin-dashboard'),
]