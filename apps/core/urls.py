from django.urls import path
from django.contrib.auth.views import LogoutView
from apps.core import views

urlpatterns = [
    path('', views.LandingPageView.as_view(), name='home'),
    path('scan/', views.ScanPageView.as_view(), name='scan_page'),
    path('scan/<uuid:scan_id>/', views.ScanResultsView.as_view(), name='scan_results'),
    path('signup/', views.RegisterView.as_view(), name='register'),
    path('signin/', views.LoginView.as_view(), name='login'),
    path('signout/', LogoutView.as_view(next_page='/'), name='logout'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('about/', views.AboutPageView.as_view(), name='about'),
    path('privacy/', views.PrivacyPageView.as_view(), name='privacy'),
    path('terms/', views.TermsPageView.as_view(), name='terms'),
    path('contact/', views.ContactPageView.as_view(), name='contact'),
    path('signin/magic-link/send/', views.send_magic_link, name='magic_link_send'),
    path('signin/magic-link/verify/', views.verify_magic_link, name='magic_link_verify'),
    path('finding/<uuid:finding_id>/action/', views.finding_action, name='finding_action'),
    path('init/', views.init_view, name='init'),
    path('health/', views.health_check, name='health_check'),
]
