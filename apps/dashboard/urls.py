"""
Dashboard app URLs.
"""
from django.urls import path
from apps.dashboard.views import LandingPageView, AdminDashboardView

urlpatterns = [
    path('', LandingPageView.as_view(), name='landing-page'),
    path('dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),
]