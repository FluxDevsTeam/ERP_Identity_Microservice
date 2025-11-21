from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated, OR
from rest_framework.filters import SearchFilter
from rest_framework.decorators import action
from django_filters.rest_framework import DjangoFilterBackend
from .serializers import TenantSerializer, BranchSerializer, ViewBranchSerializer
from .models import Tenant, Branch
from .utils import swagger_helper
from .permissions import IsSuperuser, IsCEO, IsGeneralManager, CanCreateBranch, HasActiveSubscription, IsBranchManager, HasNoRoleOrIsCEO
from rest_framework.response import Response
from .service import BillingService
from rest_framework import status


class TenantView(ModelViewSet):
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    serializer_class = TenantSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['name']
    filterset_fields = ['id', 'name', 'created_at']

    @swagger_helper("Tenant", "Check if a tenant name is available globally")
    @action(detail=False, methods=["post"], url_path="check-tenant-name")
    def check_tenant_name(self, request):
        name = (request.data.get("name") or "").strip()
        if not name:
            return Response({"available": False, "error": "Tenant name is required."}, status=status.HTTP_400_BAD_REQUEST)
        exists = Tenant.objects.filter(name__iexact=name).exists()
        if exists:
            return Response({"available": False, "error": "Tenant name is already taken."}, status=status.HTTP_200_OK)
        return Response({"available": True}, status=status.HTTP_200_OK)

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Tenant.objects.none()
        if user.is_superuser:
            return Tenant.objects.all()
        if user.is_ceo_role():
            return Tenant.objects.filter(created_by=user)
        return Tenant.objects.none()

    def get_permissions(self):
        if self.action in ['list', 'create']:
            return [IsAuthenticated(), OR(IsSuperuser(), HasNoRoleOrIsCEO())]
        if self.action in ['retrieve', 'update', 'partial_update']:
            return [IsAuthenticated(), OR(IsSuperuser(), HasNoRoleOrIsCEO())]
        if self.action == 'destroy':
            return [IsAuthenticated(), OR(IsSuperuser(), HasNoRoleOrIsCEO())]
        return [IsAuthenticated()]

    @swagger_helper("Tenant", "List all tenants (supports search and filter)")
    def list(self, *args, **kwargs):
        return super().list(*args, **kwargs)

    @swagger_helper("Tenant", "Retrieve a tenant")
    def retrieve(self, *args, **kwargs):
        return super().retrieve(*args, **kwargs)

    @swagger_helper("Tenant", "Create a tenant")
    def create(self, *args, **kwargs):
        # Check if user already has a tenant
        if self.request.user.tenant:
            return Response({
                "detail": "You already have a tenant. Each user can only create one tenant."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = self.get_serializer(data=self.request.data, context={'request': self.request})
        serializer.is_valid(raise_exception=True)
        tenant = serializer.save(created_by=self.request.user)
        
        # Assign tenant to user
        self.request.user.tenant = tenant
        self.request.user.save()
        
        # Assign CEO role to the user
        self.request.user.role = 'ceo'
        self.request.user.save()
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @swagger_helper("Tenant", "Update a tenant")
    def partial_update(self, *args, **kwargs):
        response = super().partial_update(*args, **kwargs)
        return response

    @swagger_helper("Tenant", "Delete a tenant")
    def destroy(self, *args, **kwargs):
        instance = self.get_object()
        response = super().destroy(*args, **kwargs)
        return response


class BranchView(ModelViewSet):
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    filter_backends = [DjangoFilterBackend, SearchFilter]
    search_fields = ['name']
    filterset_fields = ['id', 'name', 'tenant', 'created_at']

    @swagger_helper("Branch", "Check if a branch name is available globally")
    @action(detail=False, methods=["post"], url_path="check-branch-name")
    def check_branch_name(self, request):
        name = (request.data.get("name") or "").strip()
        if not name:
            return Response({"available": False, "error": "Branch name is required."}, status=status.HTTP_400_BAD_REQUEST)
        exists = Branch.objects.filter(name__iexact=name).exists()
        if exists:
            return Response({"available": False, "error": "Branch name is already taken."}, status=status.HTTP_200_OK)
        return Response({"available": True}, status=status.HTTP_200_OK)

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated:
            return Branch.objects.none()
        if user.is_superuser:
            return Branch.objects.all()
        if user.role in ['ceo', 'general_manager']:
            if user.tenant:
                return Branch.objects.filter(tenant=user.tenant)
            return Branch.objects.none()
        if user.role == 'branch_manager':
            if user.tenant and user.branch.exists():
                return Branch.objects.filter(tenant=user.tenant, id__in=user.branch.all())
            return Branch.objects.none()
        return Branch.objects.none()

    def get_serializer_class(self):
        if self.request.method == "GET":
            return ViewBranchSerializer
        return BranchSerializer

    def get_permissions(self):
        if self.action in ['list']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEO())]
        if self.action in ['create']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEO()), CanCreateBranch()] 
        if self.action in ['retrieve', 'update', 'partial_update']:
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEO())]
        if self.action == 'destroy':
            return [IsAuthenticated(), OR(IsSuperuser(), IsCEO())]
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
        if not self.request.user.tenant:
            return Response({
                "detail": "Authenticated user must belong to an active tenant to create a branch. Please contact your administrator."
            }, status=status.HTTP_400_BAD_REQUEST)
        
        tenant_id = self.request.user.tenant.id
        can_create, message = BillingService.can_create_branch(tenant_id, request=self.request)

        if not can_create:
            return Response({"detail": message}, status=status.HTTP_403_FORBIDDEN)

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
        instance.delete()
        return Response({"data": "Branch deleted successfully."}, status=status.HTTP_200_OK)
