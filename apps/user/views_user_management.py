from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from .user_management_serializer import UserCreateSerializer, UserListSerializer, UserUpdateSerializer
from .user_models import User
from .utils import swagger_helper
from .permissions import (IsCEOorManagerOrGeneralManagerOrBranchManager, CanViewEditUser, CanDeleteUser, HasActiveSubscription
)
from .tasks import is_celery_healthy, send_email_synchronously, send_generic_email_task
from .service import BillingService
from django.conf import settings
import requests
from rest_framework.permissions import IsAuthenticated


class UserManagementViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    permission_classes = [IsAuthenticated, IsCEOorManagerOrGeneralManagerOrBranchManager, HasActiveSubscription]
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['email', 'first_name', 'last_name']
    filterset_fields = ['role__name', 'tenant', 'branch', 'is_verified']

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        if self.action in ['list', 'retrieve']:
            return UserListSerializer
        if self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        return UserListSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return User.objects.all()
        if user.role and user.role.name in ['ceo', 'general_manager']:
            return User.objects.filter(tenant=user.tenant)
        if user.role and user.role.name in ['branch_manager', 'manager']:
            if user.tenant.branches.count() == 1:
                return User.objects.filter(tenant=user.tenant)
            else:
                return User.objects.filter(tenant=user.tenant, branch__in=user.branch.all())
        return User.objects.none()

    def get_permissions(self):
        if self.action in ['create', 'list']:
            return [IsAuthenticated(), IsCEOorManagerOrGeneralManagerOrBranchManager(), HasActiveSubscription()]
        if self.action in ['retrieve', 'update', 'partial_update']:
            return [IsAuthenticated(), CanViewEditUser()]
        if self.action == 'destroy':
            return [IsAuthenticated(), CanDeleteUser()]
        return [IsAuthenticated()]

    @swagger_helper("User Management", "Create a new user. Requires authentication (JWT) and CEO/Branch Manager role.")
    def create(self, request, *args, **kwargs):
        tenant_id = request.user.tenant.id
        current_user_count = User.objects.filter(tenant=request.user.tenant).count()
        can_create, message = BillingService.can_create_user(tenant_id, current_user_count)

        if not can_create:
            return Response({"detail": message}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        branch_ids = serializer.validated_data.get('branch', [])
        if request.user.role and request.user.role.name in ['branch_manager', 'manager'] and branch_ids:
            try:
                response = requests.get(
                    f"{settings.BILLING_MICROSERVICE_URL}/access-check/limits/",
                    headers={"Authorization": request.META.get('HTTP_AUTHORIZATION')}
                )
                response.raise_for_status()
                data = response.json()
                branch_limits = {b['branch_id']: b for b in data.get('branch_limits', [])}
                for branch_id in branch_ids:
                    branch_limit = branch_limits.get(str(branch_id))
                    if not branch_limit or not branch_limit['users_allowed']:
                        return Response({
                            "error": f"Cannot add user to branch {branch_id}. Maximum users reached."
                        }, status=status.HTTP_403_FORBIDDEN)
            except requests.RequestException:
                return Response({"error": "Unable to verify subscription limits."},
                                status=status.HTTP_503_SERVICE_UNAVAILABLE)

        user = serializer.save()
        return Response({"data": "User created successfully."}, status=status.HTTP_201_CREATED)

    @swagger_helper("User Management",
                    "List all users filtered by role, tenant, branch, and verification status. Supports search.")
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @swagger_helper("User Management", "Retrieve a single user's details.")
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @swagger_helper("User Management", "Update a user's details. Partial updates are supported.")
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=instance.email,
                email_type="confirmation",
                subject="Profile Updated",
                action="User Update",
                message=f"Your profile has been updated by {request.user.email}."
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': instance.email,
                    'email_type': "confirmation",
                    'subject': "Profile Updated",
                    'action': "User Update",
                    'message': f"Your profile has been updated by {request.user.email}."
                }
            )

        return Response({"data": "User updated successfully."}, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Update a user's details. Partial updates are supported.")
    def partial_update(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    @swagger_helper("User Management", "Delete a user from the system.")
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        email = instance.email
        instance.delete()

        if not is_celery_healthy():
            send_email_synchronously(
                user_email=email,
                email_type="confirmation",
                subject="Account Deleted",
                action="User Deletion",
                message=f"Your account has been deleted by {request.user.email}."
            )
        else:
            send_generic_email_task.apply_async(
                kwargs={
                    'user_email': email,
                    'email_type': "confirmation",
                    'subject': "Account Deleted",
                    'action': "User Deletion",
                    'message': f"Your account has been deleted by {request.user.email}."
                }
            )

        return Response({"data": "User deleted successfully."}, status=status.HTTP_200_OK)