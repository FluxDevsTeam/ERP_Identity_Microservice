from rest_framework import viewsets, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from .models import Role, Permission, UserPermission
from .serializers import RoleSerializer, PermissionSerializer, UserPermissionSerializer
from .permissions import IsCEO, IsSuperuser, HasActiveSubscription
from .service import BillingService
from .utils import OR, swagger_helper
from django.contrib.auth import get_user_model
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEO())]
        return [IsAuthenticated(), IsSuperuser(), HasActiveSubscription()]

    def get_queryset(self):
        user = self.request.user
        tenant_id = str(user.tenant.id) if user.tenant else 'None'
        if user.is_superuser:
            logger.info(
                f"PermissionViewSet: Superuser accessing all permissions, user={user.email}, tenant_id={tenant_id}")
            return Permission.objects.all()
        if user.tenant:
            try:
                subscription_details = BillingService.fetch_subscription_details(tenant_id, self.request)
                if subscription_details and subscription_details.get("access"):
                    industry = subscription_details.get("plan", {}).get("industry", "Other")
                    logger.info(
                        f"PermissionViewSet: Filtering permissions for user={user.email}, tenant_id={tenant_id}, industry={industry}")
                    return Permission.objects.filter(industry__in=[industry, 'Other'])
            except Exception as e:
                logger.error(
                    f"PermissionViewSet: Failed to fetch subscription details for tenant_id={tenant_id}: {str(e)}")
        logger.warning(
            f"PermissionViewSet: No valid tenant or subscription for user={user.email}, tenant_id={tenant_id}")
        return Permission.objects.none()

    @swagger_helper(tags="Permissions", model="Permission")
    def list(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(f"PermissionViewSet: Listing permissions for user={request.user.email}, tenant_id={tenant_id}")
        return super().list(request, *args, **kwargs)

    @swagger_helper(tags="Permissions", model="Permission")
    def retrieve(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"PermissionViewSet: Retrieving permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().retrieve(request, *args, **kwargs)

    @swagger_helper(tags="Permissions", model="Permission")
    def create(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(f"PermissionViewSet: Creating permission for user={request.user.email}, tenant_id={tenant_id}")
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        logger.info(
            f"PermissionViewSet: Permission created successfully, id={serializer.data['id']}, user={request.user.email}, tenant_id={tenant_id}")
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @swagger_helper(tags="Permissions", model="Permission")
    def update(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"PermissionViewSet: Updating permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().update(request, *args, **kwargs)

    @swagger_helper(tags="Permissions", model="Permission")
    def partial_update(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"PermissionViewSet: Partially updating permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().partial_update(request, *args, **kwargs)

    @swagger_helper(tags="Permissions", model="Permission")
    def destroy(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"PermissionViewSet: Deleting permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        permission = self.get_object()
        if permission.default_roles.exists() or permission.userpermission_set.exists():
            logger.warning(
                f"PermissionViewSet: Cannot delete permission id={permission.id} as it is assigned, user={request.user.email}, tenant_id={tenant_id}")
            return Response(
                {"error": "Cannot delete permission because it is assigned to roles or users."},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().destroy(request, *args, **kwargs)


class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEO())]
        return [IsAuthenticated(), OR(IsSuperuser(), IsCEO()), HasActiveSubscription()]

    def get_queryset(self):
        user = self.request.user
        tenant_id = str(user.tenant.id) if user.tenant else 'None'
        if user.is_superuser:
            logger.info(f"RoleViewSet: Superuser accessing all roles, user={user.email}, tenant_id={tenant_id}")
            return Role.objects.all()
        if user.tenant:
            try:
                subscription_details = BillingService.fetch_subscription_details(tenant_id, self.request)
                if subscription_details and subscription_details.get("access"):
                    industry = subscription_details.get("plan", {}).get("industry", "Other")
                    logger.info(
                        f"RoleViewSet: Filtering roles for user={user.email}, tenant_id={tenant_id}, industry={industry}")
                    return Role.objects.filter(industry__in=[industry, 'Other'])
            except Exception as e:
                logger.error(f"RoleViewSet: Failed to fetch subscription details for tenant_id={tenant_id}: {str(e)}")
        logger.warning(f"RoleViewSet: No valid tenant or subscription for user={user.email}, tenant_id={tenant_id}")
        return Role.objects.none()

    @swagger_helper(tags="Roles", model="Role")
    def list(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(f"RoleViewSet: Listing roles for user={request.user.email}, tenant_id={tenant_id}")
        return super().list(request, *args, **kwargs)

    @swagger_helper(tags="Roles", model="Role")
    def retrieve(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"RoleViewSet: Retrieving role id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().retrieve(request, *args, **kwargs)

    @swagger_helper(tags="Roles", model="Role")
    def create(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(f"RoleViewSet: Creating role for user={request.user.email}, tenant_id={tenant_id}")
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        logger.info(
            f"RoleViewSet: Role created successfully, id={serializer.data['id']}, user={request.user.email}, tenant_id={tenant_id}")
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    @swagger_helper(tags="Roles", model="Role")
    def update(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"RoleViewSet: Updating role id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().update(request, *args, **kwargs)

    @swagger_helper(tags="Roles", model="Role")
    def partial_update(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"RoleViewSet: Partially updating role id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().partial_update(request, *args, **kwargs)

    @swagger_helper(tags="Roles", model="Role")
    def destroy(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"RoleViewSet: Deleting role id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        role = self.get_object()
        if User.objects.filter(role=role).exists():
            logger.warning(
                f"RoleViewSet: Cannot delete role id={role.id} as it is assigned to users, user={request.user.email}, tenant_id={tenant_id}")
            return Response(
                {"error": "Cannot delete role because it is assigned to one or more users."},
                status=status.HTTP_400_BAD_REQUEST
            )
        return super().destroy(request, *args, **kwargs)


class UserPermissionViewSet(viewsets.ModelViewSet):
    queryset = UserPermission.objects.all()
    serializer_class = UserPermissionSerializer

    def get_permissions(self):
        if self.action in ['list', 'retrieve']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEO())]
        return [IsAuthenticated(), OR(IsSuperuser(), IsCEO()), HasActiveSubscription()]

    def get_queryset(self):
        user = self.request.user
        tenant_id = str(user.tenant.id) if user.tenant else 'None'
        if user.is_superuser:
            logger.info(
                f"UserPermissionViewSet: Superuser accessing all permissions, user={user.email}, tenant_id={tenant_id}")
            return UserPermission.objects.all()
        if user.tenant:
            try:
                subscription_details = BillingService.fetch_subscription_details(tenant_id, self.request)
                if subscription_details and subscription_details.get("access"):
                    logger.info(
                        f"UserPermissionViewSet: Filtering permissions for user={user.email}, tenant_id={tenant_id}")
                    return UserPermission.objects.filter(user__tenant=user.tenant)
            except Exception as e:
                logger.error(
                    f"UserPermissionViewSet: Failed to fetch subscription details for tenant_id={tenant_id}: {str(e)}")
        logger.warning(
            f"UserPermissionViewSet: No valid tenant or subscription for user={user.email}, tenant_id={tenant_id}")
        return UserPermission.objects.none()

    @swagger_helper(tags="User Permissions", model="User Permission")
    def list(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(f"UserPermissionViewSet: Listing permissions for user={request.user.email}, tenant_id={tenant_id}")
        return super().list(request, *args, **kwargs)

    @swagger_helper(tags="User Permissions", model="User Permission")
    def retrieve(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"UserPermissionViewSet: Retrieving permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().retrieve(request, *args, **kwargs)

    @swagger_helper(tags="User Permissions", model="User Permission")
    def create(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(f"UserPermissionViewSet: Creating permission for user={request.user.email}, tenant_id={tenant_id}")
        user_id = request.data.get('user_id')
        if not user_id:
            logger.warning(
                f"UserPermissionViewSet: user_id is required, user={request.user.email}, tenant_id={tenant_id}")
            return Response({"error": "user_id is required"}, status=status.HTTP_400_BAD_REQUEST)
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            logger.warning(
                f"UserPermissionViewSet: User not found, user_id={user_id}, user={request.user.email}, tenant_id={tenant_id}")
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        logger.info(
            f"UserPermissionViewSet: Permission created for user_id={user_id}, user={request.user.email}, tenant_id={tenant_id}")
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @swagger_helper(tags="User Permissions", model="User Permission")
    def update(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"UserPermissionViewSet: Updating permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().update(request, *args, **kwargs)

    @swagger_helper(tags="User Permissions", model="User Permission")
    def partial_update(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"UserPermissionViewSet: Partially updating permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().partial_update(request, *args, **kwargs)

    @swagger_helper(tags="User Permissions", model="User Permission")
    def destroy(self, request, *args, **kwargs):
        tenant_id = str(request.user.tenant.id) if request.user.tenant else 'None'
        logger.info(
            f"UserPermissionViewSet: Deleting permission id={kwargs.get('pk')} for user={request.user.email}, tenant_id={tenant_id}")
        return super().destroy(request, *args, **kwargs)
