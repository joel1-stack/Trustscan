"""
Reconnaissance app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.reconnaissance.views import (
    FindingViewSet, InspectorResultViewSet, TechnologyFingerprintViewSet,
    HTTPResponseViewSet, SecurityHeaderFindingViewSet, SSLConfigurationViewSet,
    EmailSecurityRecordViewSet, BreachRecordViewSet, ExposedServiceViewSet,
    ReputationFindingViewSet, GitHubRepositoryViewSet, APIEndpointViewSet
)

router = DefaultRouter()
router.register(r'findings', FindingViewSet, basename='finding')
router.register(r'inspector-results', InspectorResultViewSet, basename='inspectorresult')
router.register(r'technologies', TechnologyFingerprintViewSet, basename='technologyfingerprint')
router.register(r'http-responses', HTTPResponseViewSet, basename='httpresponse')
router.register(r'security-headers', SecurityHeaderFindingViewSet, basename='securityheaderfinding')
router.register(r'ssl-configs', SSLConfigurationViewSet, basename='sslconfiguration')
router.register(r'email-security', EmailSecurityRecordViewSet, basename='emailsecurityrecord')
router.register(r'breaches', BreachRecordViewSet, basename='breachrecord')
router.register(r'exposed-services', ExposedServiceViewSet, basename='exposedservice')
router.register(r'reputation', ReputationFindingViewSet, basename='reputationfinding')
router.register(r'github-repos', GitHubRepositoryViewSet, basename='githubrepository')
router.register(r'api-endpoints', APIEndpointViewSet, basename='apiendpoint')

urlpatterns = [
    path('', include(router.urls)),
]