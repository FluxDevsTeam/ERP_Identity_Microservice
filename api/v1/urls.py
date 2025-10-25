from django.urls import path, include

urlpatterns = [
    path("", include("apps.tenant.urls")),
    path("user/", include("apps.user.urls")),
    path("", include("apps.role.urls")),
]
