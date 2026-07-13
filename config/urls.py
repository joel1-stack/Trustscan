"""
URL configuration for TrustScan project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularSwaggerView,
    SpectacularRedocView,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
    
    # Health Check
    path('health/', include('apps.core.urls')),
    
    # Apps URLs
    path('', include('apps.dashboard.urls')),
    path('api/v1/accounts/', include('apps.accounts.urls')),
    path('api/v1/domains/', include('apps.domains.urls')),
    path('api/v1/scanner/', include('apps.scanner.urls')),
    path('api/v1/discovery/', include('apps.discovery.urls')),
    path('api/v1/reconnaissance/', include('apps.reconnaissance.urls')),
    path('api/v1/correlation/', include('apps.correlation.urls')),
    path('api/v1/scoring/', include('apps.scoring.urls')),
    path('api/v1/intelligence/', include('apps.intelligence.urls')),
    path('api/v1/reports/', include('apps.reports.urls')),
    path('api/v1/billing/', include('apps.billing.urls')),
    path('api/v1/dashboard/', include('apps.dashboard.urls')),
    
    # Public API (for TrustLayer integration)
    path('api/v1/public/', include('apps.api.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    
    try:
        import debug_toolbar
        urlpatterns = [
            path('__debug__/', include(debug_toolbar.urls)),
        ] + urlpatterns
    except ImportError:
        pass