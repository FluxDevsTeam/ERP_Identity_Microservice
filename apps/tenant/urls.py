from django.urls import path, include
from .views import BranchView, TenantView
from rest_framework.routers import DefaultRouter

router = DefaultRouter()
router.register("tenant", TenantView, basename="tenant")
router.register("branch", BranchView, basename="branch")
urlpatterns = [
    path("", include(router.urls))
]
