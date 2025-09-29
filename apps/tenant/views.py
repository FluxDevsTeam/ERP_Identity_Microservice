# apps/tenant/views.py
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated
from rest_framework.filters import SearchFilter
from django_filters.rest_framework import DjangoFilterBackend
from .serializers import TenantSerializer, BranchSerializer, ViewBranchSerializer
from .models import Tenant, Branch
from .utils import swagger_helper
from .permissions import IsSuperuser, IsCEO, HasActiveSubscription, IsBranchManager, IsCEOorBranchManager, \
    CanViewEditTenant, CanDeleteTenant, CanViewEditBranch, CanDeleteBranch
from rest_framework.response import Response
from rest_framework import status


class TenantView(ModelViewSet):
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    serializer_class = TenantSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['name']
    filterset_fields = ['id', 'name', 'created_at']

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Tenant.objects.none()
        if user.is_superuser:
            return Tenant.objects.all()
        if user.role == 'ceo':
            return Tenant.objects.filter(id=user.tenant.id) if user.tenant else Tenant.objects.none()
        return Tenant.objects.none()

    def get_permissions(self):
        if self.action in ['list', 'create']:
            return [IsAuthenticated(), IsSuperuser() | IsCEO()]
        if self.action in ['retrieve', 'update', 'partial_update']:
            return [IsAuthenticated(), CanViewEditTenant()]
        if self.action == 'destroy':
            return [IsAuthenticated(), CanDeleteTenant()]
        return [IsAuthenticated()]

    @swagger_helper("Tenant", "List all tenants (supports search and filter)")
    def list(self, *args, **kwargs):
        return super().list(*args, **kwargs)

    @swagger_helper("Tenant", "Retrieve a tenant")
    def retrieve(self, *args, **kwargs):
        return super().retrieve(*args, **kwargs)

    @swagger_helper("Tenant", "Create a tenant")
    def create(self, *args, **kwargs):
        serializer = self.get_serializer(data=self.request.data, context={'request': self.request})
        serializer.is_valid(raise_exception=True)
        tenant = serializer.save(created_by=self.request.user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @swagger_helper("Tenant", "Update a tenant")
    def partial_update(self, *args, **kwargs):
        response = super().partial_update(*args, **kwargs)
        instance = self.get_object()

        return response

    @swagger_helper("Tenant", "Delete a tenant")
    def destroy(self, *args, **kwargs):
        instance = self.get_object()
        email = self.request.user.email
        response = super().destroy(*args, **kwargs)
        return response


class BranchView(ModelViewSet):
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['name']
    filterset_fields = ['id', 'name', 'tenant', 'created_at']

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Branch.objects.none()
        if user.is_superuser:
            return Branch.objects.all()
        if user.role == 'ceo':
            return Branch.objects.filter(tenant=user.tenant) if user.tenant else Branch.objects.none()
        if user.role == 'Branch_manager':
            return Branch.objects.filter(tenant=user.tenant,
                                         id__in=user.branch.all()) if user.tenant else Branch.objects.none()
        return Branch.objects.none()

    def get_serializer_class(self):
        if self.request.method == "GET":
            return ViewBranchSerializer
        return BranchSerializer

    def get_permissions(self):
        if self.action in ['list', 'create']:
            return [IsAuthenticated(), IsCEOorBranchManager(), HasActiveSubscription()]
        if self.action in ['retrieve', 'update', 'partial_update']:
            return [IsAuthenticated(), CanViewEditBranch()]
        if self.action == 'destroy':
            return [IsAuthenticated(), CanDeleteBranch()]
        return [IsAuthenticated()]

    @swagger_helper("Branch", "List all branches (supports search and filter)")
    def list(self, *args, **kwargs):
        return super().list(*args, **kwargs)

    @swagger_helper("Branch", "Retrieve a branch")
    def retrieve(self, *args, **kwargs):
        return super().retrieve(*args, **kwargs)

    @swagger_helper("Branch", "Create a branch")
    def create(self, *args, **kwargs):
        serializer = self.get_serializer(data=self.request.data, context={'request': self.request})
        serializer.is_valid(raise_exception=True)
        branch = serializer.save(tenant=self.request.user.tenant)
        return Response({"data": "Branch created successfully."}, status=status.HTTP_201_CREATED)

    @swagger_helper("Branch", "Update a branch")
    def partial_update(self, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=self.request.data, partial=True,
                                         context={'request': self.request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"data": "Branch updated successfully."}, status=status.HTTP_200_OK)

    @swagger_helper("Branch", "Delete a branch")
    def destroy(self, *args, **kwargs):
        instance = self.get_object()
        email = self.request.user.email
        instance.delete()
        return Response({"data": "Branch deleted successfully."}, status=status.HTTP_200_OK)
