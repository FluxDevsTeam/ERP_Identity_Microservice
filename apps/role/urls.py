from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import PermissionsConfigView

router = DefaultRouter()

urlpatterns = [
    path('config/', PermissionsConfigView.as_view(), name='permissions-config'),
]
