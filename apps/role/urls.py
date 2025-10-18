from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    PermissionViewSet, RoleViewSet, UserPermissionViewSet
)

router = DefaultRouter()
router.register('permissions', PermissionViewSet)
router.register('roles', RoleViewSet)
router.register('user-permissions', UserPermissionViewSet)

urlpatterns = [
    path('', include(router.urls)),
]
