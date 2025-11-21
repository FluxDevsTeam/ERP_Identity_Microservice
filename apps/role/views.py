from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import PERMISSIONS_CONFIG
from .utils import swagger_helper

class PermissionsConfigView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_helper(tags="Permissions Config", model="Permissions Config")
    def get(self, request):
        """Return the static permissions configuration."""
        return Response(PERMISSIONS_CONFIG)
