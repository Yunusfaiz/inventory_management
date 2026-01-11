from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, RoleViewSet, PermissionViewSet, UserActivityViewSet

app_name = 'users'

router = DefaultRouter()
router.register(r'users', UserViewSet, basename='user')
router.register(r'roles', RoleViewSet, basename='role')
router.register(r'permissions', PermissionViewSet, basename='permission')
router.register(r'activities', UserActivityViewSet, basename='activity')

urlpatterns = [
    path('', include(router.urls)),
    
    # Authentication endpoints (alternative to ViewSet actions)
    path('auth/register/', UserViewSet.as_view({'post': 'register'}), name='register'),
    path('auth/login/', UserViewSet.as_view({'post': 'login'}), name='login'),
    path('auth/logout/', UserViewSet.as_view({'post': 'logout'}), name='logout'),
    
    # Profile endpoints
    path('profile/me/', UserViewSet.as_view({'get': 'me'}), name='profile-me'),
    path('profile/update/', UserViewSet.as_view({'put': 'update_profile', 'patch': 'update_profile'}), name='profile-update'),
    path('profile/change-password/', UserViewSet.as_view({'post': 'change_password'}), name='change-password'),
]