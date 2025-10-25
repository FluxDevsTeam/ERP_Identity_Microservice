from rest_framework.pagination import PageNumberPagination

from .serializers_user_management import UserListSerializer, TempUserSerializer
from .models_auth import TempUser, PasswordChangeRequest
from django.utils import timezone
from django.contrib.auth.hashers import make_password, check_password
from rest_framework import viewsets, status
from rest_framework.response import Response
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from .serializers_user_management import (
    UserCreateSerializer, UserUpdateSerializer,
    AdminPasswordChangeSerializer, AdminVerifyPasswordChangeSerializer,
    ResendPasswordChangeOTPSerializer, UserVerifySerializer, UserResendOTPSerializer
)
from .models import User
from .utils import swagger_helper
from .permissions import (
    IsCEOorManagerOrGeneralManagerOrBranchManager, CanViewEditUser, CanDeleteUser,
    HasActiveSubscription, IsCEO, IsSuperuser, CanManageTempUser
)
from .services import send_email_via_service
from django.conf import settings
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
import random


class OR:
    def __init__(self, *perms):
        self.perms = perms

    def __call__(self):
        return self

    def has_permission(self, request, view):
        return any(perm.has_permission(request, view) for perm in self.perms)

    def has_object_permission(self, request, view, obj):
        return any(
            hasattr(perm, 'has_object_permission') and perm.has_object_permission(request, view, obj)
            for perm in self.perms
        )


class UserManagementViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['email', 'first_name', 'last_name']
    filterset_fields = ['role__name', 'tenant', 'branch', 'is_verified']

    def get_permissions(self):
        if self.action == 'create':
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEOorManagerOrGeneralManagerOrBranchManager()), HasActiveSubscription()]
        if self.action in ['retrieve', 'update', 'partial_update', 'admin_password_change', 'verify_admin_password_change', 'resend_admin_password_otp']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEOorManagerOrGeneralManagerOrBranchManager()), CanViewEditUser()]
        if self.action == 'destroy':
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEOorManagerOrGeneralManagerOrBranchManager()), CanDeleteUser()]
        if self.action in ['verify_otp', 'resend_otp']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEOorManagerOrGeneralManagerOrBranchManager())]
        return [IsAuthenticated(), OR(IsSuperuser(), IsCEOorManagerOrGeneralManagerOrBranchManager())]

    def get_serializer_class(self):
        if self.action == 'create':
            return UserCreateSerializer
        if self.action in ['list', 'retrieve']:
            return UserListSerializer
        if self.action in ['update', 'partial_update']:
            return UserUpdateSerializer
        if self.action == 'admin_password_change':
            return AdminPasswordChangeSerializer
        if self.action == 'verify_admin_password_change':
            return AdminVerifyPasswordChangeSerializer
        if self.action == 'resend_admin_password_otp':
            return ResendPasswordChangeOTPSerializer
        if self.action == 'verify_otp':
            return UserVerifySerializer
        if self.action == 'resend_otp':
            return UserResendOTPSerializer
        return UserListSerializer

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return User.objects.all()
        if user.tenant:
            return User.objects.filter(tenant=user.tenant)
        return User.objects.none()

    @swagger_helper("User Management", "Create a new user. Requires authentication (JWT) and CEO/Branch Manager/General Manager role.")
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        temp_user = serializer.save()
        return Response({"data": "User creation initiated. OTP sent to user's email for verification.", "email": temp_user.email}, status=status.HTTP_201_CREATED)

    @swagger_helper("User Management", "List all users filtered by role, tenant, branch, and verification status. Supports search.")
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
        send_email_via_service({
            'user_email': instance.email,
            'email_type': 'confirmation',
            'subject': 'Profile Updated',
            'action': 'User Update',
            'message': f'Your profile has been updated by {request.user.email}.'
        })
        return Response({"data": "User updated successfully."}, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Update a user's details. Partial updates are supported.")
    def partial_update(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    @swagger_helper("User Management", "Delete a user from the system.")
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        email = instance.email
        instance.delete()
        send_email_via_service({
            'user_email': email,
            'email_type': 'confirmation',
            'subject': 'Account Deleted',
            'action': 'User Deletion',
            'message': f'Your account has been deleted by {request.user.email}.'
        })
        return Response({"data": "User deleted successfully."}, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Verify a user's OTP for email verification.")
    @action(detail=False, methods=['post'], url_path='verify-otp')
    def verify_otp(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "data": "Verification successful.",
            "user": UserListSerializer(user).data
        }, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Resend OTP for a user's email verification.")
    @action(detail=False, methods=['post'], url_path='resend-otp')
    def resend_otp(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response({"data": result['message']}, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Request password change for a user.")
    @action(detail=True, methods=['post'], url_path='admin-password-change')
    def admin_password_change(self, request, pk=None):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data['new_password']
        PasswordChangeRequest.objects.filter(user=user, requested_by=request.user, is_verified=False).delete()
        otp = str(random.randint(100000, 999999))
        PasswordChangeRequest.objects.create(
            user=user,
            otp=make_password(otp),
            new_password=make_password(new_password),
            requested_by=request.user,
            created_at=timezone.now()
        )
        send_email_via_service({
            'user_email': request.user.email,
            'email_type': 'otp',
            'subject': 'Password Change Request OTP',
            'action': 'Password Change',
            'message': f'You have requested to change the password for {user.email}. Use the OTP below to confirm.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/admin-password-change/?email={user.email}",
            'link_text': 'Confirm Password Change'
        })
        return Response({"data": "An OTP has been sent to your email for verification."}, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Verify password change OTP.")
    @action(detail=True, methods=['post'], url_path='verify-admin-password-change')
    def verify_admin_password_change(self, request, pk=None):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        otp = serializer.validated_data['otp']
        password_change_request = PasswordChangeRequest.objects.filter(user=user, requested_by=request.user, is_verified=False).first()
        if not password_change_request:
            return Response({"data": "No pending password change request found."}, status=status.HTTP_400_BAD_REQUEST)
        if not check_password(otp, password_change_request.otp):
            return Response({"data": "Incorrect OTP."}, status=status.HTTP_400_BAD_REQUEST)
        if (timezone.now() - password_change_request.created_at).total_seconds() > 300:
            return Response({"data": "OTP has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(password_change_request.new_password)
        user.save()
        password_change_request.is_verified = True
        password_change_request.save()
        send_email_via_service({
            'user_email': user.email,
            'email_type': 'confirmation',
            'subject': 'Password Changed',
            'action': 'Password Change',
            'message': f'Your password has been changed by {request.user.email}.'
        })
        return Response({"data": "Password changed successfully."}, status=status.HTTP_200_OK)

    @swagger_helper("User Management", "Resend OTP for admin password change.")
    @action(detail=True, methods=['post'], url_path='resend-admin-password-otp')
    def resend_admin_password_otp(self, request, pk=None):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        password_change_request = PasswordChangeRequest.objects.filter(user=user, requested_by=request.user, is_verified=False).first()
        if not password_change_request:
            return Response({"data": "No pending password change request found."}, status=status.HTTP_400_BAD_REQUEST)
        otp = str(random.randint(100000, 999999))
        password_change_request.otp = make_password(otp)
        password_change_request.created_at = timezone.now()
        password_change_request.save()
        send_email_via_service({
            'user_email': request.user.email,
            'email_type': 'otp',
            'subject': 'Password Change Request OTP - Resent',
            'action': 'Password Change',
            'message': f'You have requested to change the password for {user.email}. Use the OTP below to confirm.',
            'otp': otp,
            'link': f"{settings.FRONTEND_PATH}/admin-password-change/?email={user.email}",
            'link_text': 'Confirm Password Change'
        })
        return Response({"data": "A new OTP has been sent to your email."}, status=status.HTTP_200_OK)


class TempUserViewSet(viewsets.ModelViewSet):
    queryset = TempUser.objects.all()
    serializer_class = TempUserSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['email', 'first_name', 'last_name']
    filterset_fields = ['role__name', 'tenant', 'branch']
    pagination_class = PageNumberPagination

    def get_permissions(self):
        return [IsAuthenticated(), OR(IsSuperuser(), IsCEOorManagerOrGeneralManagerOrBranchManager()), CanManageTempUser(), HasActiveSubscription()]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser:
            return TempUser.objects.all()
        if user.tenant:
            return TempUser.objects.filter(tenant=user.tenant)
        return TempUser.objects.none()

    @swagger_helper("Temp User Management", "List all pending temp users filtered by role, tenant, and branch. Supports search.")
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)  # Use default list method with pagination

    @swagger_helper("Temp User Management", "Retrieve a single pending temp user's details.")
    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_helper("Temp User Management", "Delete a pending temp user from the system.")
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        email = instance.email
        instance.delete()
        send_email_via_service({
            'user_email': email,
            'email_type': 'confirmation',
            'subject': 'Pending Registration Canceled',
            'action': 'Temp User Deletion',
            'message': f'Your pending registration has been canceled by {request.user.email}.'
        })
        return Response({"data": "Pending temp user deleted successfully."}, status=status.HTTP_200_OK)

    # Disable create, update, and partial_update actions
    def create(self, request, *args, **kwargs):
        return Response({"detail": "Creating temp users is handled via UserManagementViewSet."}, status=status.HTTP_403_FORBIDDEN)

    def update(self, request, *args, **kwargs):
        return Response({"detail": "Updating temp users is not allowed."}, status=status.HTTP_403_FORBIDDEN)

    def partial_update(self, request, *args, **kwargs):
        return Response({"detail": "Updating temp users is not allowed."}, status=status.HTTP_403_FORBIDDEN)