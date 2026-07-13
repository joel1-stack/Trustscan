from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from rest_framework.serializers import ModelSerializer

from apps.accounts.models import User, Organization, Team, Membership, Invitation, UserAPIKey


class UserSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class OrganizationSerializer(ModelSerializer):
    class Meta:
        model = Organization
        fields = '__all__'


class TeamSerializer(ModelSerializer):
    class Meta:
        model = Team
        fields = '__all__'


class MembershipSerializer(ModelSerializer):
    class Meta:
        model = Membership
        fields = '__all__'


class InvitationSerializer(ModelSerializer):
    class Meta:
        model = Invitation
        fields = '__all__'


class UserAPIKeySerializer(ModelSerializer):
    class Meta:
        model = UserAPIKey
        fields = '__all__'


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]


class OrganizationViewSet(viewsets.ModelViewSet):
    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [AllowAny]


class TeamViewSet(viewsets.ModelViewSet):
    queryset = Team.objects.all().select_related('organization')
    serializer_class = TeamSerializer
    permission_classes = [AllowAny]


class MembershipViewSet(viewsets.ModelViewSet):
    queryset = Membership.objects.all().select_related('user', 'organization', 'team')
    serializer_class = MembershipSerializer
    permission_classes = [AllowAny]


class InvitationViewSet(viewsets.ModelViewSet):
    queryset = Invitation.objects.all().select_related('organization', 'team', 'invited_by')
    serializer_class = InvitationSerializer
    permission_classes = [AllowAny]


class UserAPIKeyViewSet(viewsets.ModelViewSet):
    queryset = UserAPIKey.objects.all().select_related('organization', 'created_by')
    serializer_class = UserAPIKeySerializer
    permission_classes = [AllowAny]
