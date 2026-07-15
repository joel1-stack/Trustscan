from django.urls import path
from django.contrib.auth.views import LogoutView
from apps.core import views

urlpatterns = [
    path('', views.LandingPageView.as_view(), name='home'),
    path('scan/', views.ScanPageView.as_view(), name='scan_page'),
    path('scan/<uuid:scan_id>/', views.ScanResultsView.as_view(), name='scan_results'),
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(next_page='/'), name='logout'),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
    path('about/', views.AboutPageView.as_view(), name='about'),
    path('privacy/', views.PrivacyPageView.as_view(), name='privacy'),
    path('terms/', views.TermsPageView.as_view(), name='terms'),
    path('contact/', views.ContactPageView.as_view(), name='contact'),
    path('auth/magic-link/send/', views.send_magic_link, name='magic_link_send'),
    path('auth/magic-link/verify/', views.verify_magic_link, name='magic_link_verify'),
    path('init/', views.init_view, name='init'),
]
