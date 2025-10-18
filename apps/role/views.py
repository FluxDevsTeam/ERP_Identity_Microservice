# roles/views.py
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from .serializers import (
    PermissionSerializer, PermissionCreateSerializer,
    RoleSerializer, RoleCreateSerializer,
    UserPermissionSerializer, UserPermissionCreateSerializer, UserPermissionListSerializer
)
from .models import Permission, Role, UserPermission
from .permissions import IsCEO
from django.conf import settings


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    permission_classes = [IsAuthenticated, IsCEO]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['industry', 'category']

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return PermissionCreateSerializer
        return PermissionSerializer


class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    permission_classes = [IsAuthenticated, IsCEO]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['industry']

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return RoleCreateSerializer
        return RoleSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return Role.objects.all()
        if user.tenant and user.tenant.subscription:
            tier = user.tenant.subscription.plan.tier_level
            industry = user.tenant.subscription.plan.industry
            return Role.objects.filter(
                industry=industry,
                subscription_tiers__overlap=[tier]
            )
        return Role.objects.none()


class UserPermissionViewSet(viewsets.ModelViewSet):
    queryset = UserPermission.objects.all()
    permission_classes = [IsAuthenticated, IsCEO]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['user', 'permission', 'granted']

    def get_serializer_class(self):
        if self.action in ['create', 'update', 'partial_update']:
            return UserPermissionCreateSerializer
        if self.action == 'list':
            return UserPermissionListSerializer
        return UserPermissionSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return UserPermission.objects.all()
        if user.tenant:
            return UserPermission.objects.filter(
                user__tenant=user.tenant
            )
        return UserPermission.objects.none()

    @action(detail=False, methods=['get'], url_path='user/(?P<user_id>[^/.]+)')
    def for_user(self, request, user_id=None):
        """Get all user permissions for a specific user."""
        try:
            user = settings.AUTH_USER_MODEL.objects.get(id=user_id)
            if user.tenant != request.user.tenant:
                return Response({'error': 'Unauthorized'}, status=status.HTTP_403_FORBIDDEN)
            queryset = UserPermission.objects.filter(user=user)
            serializer = self.get_serializer(queryset, many=True)
            return Response(serializer.data)
        except settings.AUTH_USER_MODEL.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)