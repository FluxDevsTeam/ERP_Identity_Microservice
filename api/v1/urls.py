from django.urls import path, include

urlpatterns = [
    path("tenant/", include("apps.tenant.urls")),
    path("user/", include("apps.user.urls"))
]
