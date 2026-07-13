"""
Accounts app URLs.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from apps.accounts.views import (
    UserViewSet, OrganizationViewSet, TeamViewSet,
    MembershipViewSet, InvitationViewSet, UserAPIKeyViewSet
)

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'organizations', OrganizationViewSet, basename='organization')
router.register(r'teams', TeamViewSet, basename='team')
router.register(r'memberships', MembershipViewSet, basename='membership')
router.register(r'invitations', InvitationViewSet, basename='invitation')
router.register(r'api-keys', UserAPIKeyViewSet, basename='user-apikey')

urlpatterns = [
    path('', include(router.urls)),
]