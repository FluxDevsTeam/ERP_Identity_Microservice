from rest_framework.viewsets import ModelViewSet
from .serializers import TenantSerializer, BranchSerializer, ViewBranchSerializer
from .models import Tenant, Branch
from .utils import swagger_helper


class TenantView(ModelViewSet):
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    serializer_class = TenantSerializer
    queryset = Tenant.objects.all()

    @swagger_helper("Tenant", "Tenant")
    def list(self, *args, **kwargs):
        return super().list(*args, **kwargs)

    @swagger_helper("Tenant", "Tenant")
    def retrieve(self, *args, **kwargs):
        return super().retrieve(*args, **kwargs)

    @swagger_helper("Tenant", "Tenant")
    def create(self, *args, **kwargs):
        return super().create(*args, **kwargs)

    @swagger_helper("Tenant", "Tenant")
    def partial_update(self, *args, **kwargs):
        return super().partial_update(*args, **kwargs)

    @swagger_helper("Tenant", "Tenant")
    def destroy(self, *args, **kwargs):
        return super().destroy(*args, **kwargs)


class BranchView(ModelViewSet):
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    def get_queryset(self):
        Branch.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        if self.request.method == "GET":
            return ViewBranchSerializer
        return BranchSerializer

    @swagger_helper("Branch", "Branch")
    def list(self, *args, **kwargs):
        return super().list(*args, **kwargs)

    @swagger_helper("Branch", "Branch")
    def retrieve(self, *args, **kwargs):
        return super().retrieve(*args, **kwargs)

    @swagger_helper("Branch", "Branch")
    def create(self, *args, **kwargs):
        return super().create(*args, **kwargs)

    @swagger_helper("Branch", "Branch")
    def partial_update(self, *args, **kwargs):
        return super().partial_update(*args, **kwargs)

    @swagger_helper("Branch", "Branch")
    def destroy(self, *args, **kwargs):
        return super().destroy(*args, **kwargs)
