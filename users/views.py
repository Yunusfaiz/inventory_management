from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from django.contrib.auth import login, logout
from django.utils import timezone
from .models import User, UserProfile, Role, Permission, UserActivity
from .serializers import (
    UserSerializer, UserListSerializer, UserProfileSerializer,
    RoleSerializer, PermissionSerializer, UserActivitySerializer,
    UserRegistrationSerializer, UserLoginSerializer, ChangePasswordSerializer
)


class RoleViewSet(viewsets.ModelViewSet):
    """ViewSet for Role model"""
    queryset = Role.objects.all()
    serializer_class = RoleSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Filter active roles by default"""
        queryset = Role.objects.all()
        is_active = self.request.query_params.get('is_active', None)
        
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        return queryset


class PermissionViewSet(viewsets.ModelViewSet):
    """ViewSet for Permission model"""
    queryset = Permission.objects.all()
    serializer_class = PermissionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Filter permissions by role if provided"""
        queryset = Permission.objects.all()
        role_id = self.request.query_params.get('role', None)
        
        if role_id:
            queryset = queryset.filter(role_id=role_id)
        
        return queryset


class UserViewSet(viewsets.ModelViewSet):
    """ViewSet for User model"""
    queryset = User.objects.all()
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_class(self):
        """Use different serializers for list and detail views"""
        if self.action == 'list':
            return UserListSerializer
        return UserSerializer
    
    def get_queryset(self):
        """Filter users based on query parameters"""
        queryset = User.objects.select_related('role', 'profile').all()
        
        # Filter by role
        role_id = self.request.query_params.get('role', None)
        if role_id:
            queryset = queryset.filter(role_id=role_id)
        
        # Filter by active status
        is_active = self.request.query_params.get('is_active', None)
        if is_active is not None:
            queryset = queryset.filter(is_active=is_active.lower() == 'true')
        
        # Search by name, email, or username
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(username__icontains=search) |
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        
        return queryset
    
    @action(detail=False, methods=['post'])
    def register(self, request):
        """Register a new user"""
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token, created = Token.objects.get_or_create(user=user)
            
            # Log activity
            UserActivity.objects.create(
                user=user,
                action=UserActivity.LOGIN,
                description="User registered",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({
                'user': UserSerializer(user).data,
                'token': token.key
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        """User login"""
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            
            # Update last login
            user.last_login = timezone.now()
            user.save(update_fields=['last_login'])
            
            # Log activity
            UserActivity.objects.create(
                user=user,
                action=UserActivity.LOGIN,
                description="User logged in",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            return Response({
                'user': UserSerializer(user).data,
                'token': token.key
            })
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def logout(self, request):
        """User logout"""
        if request.user.is_authenticated:
            # Log activity
            UserActivity.objects.create(
                user=request.user,
                action=UserActivity.LOGOUT,
                description="User logged out",
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Delete token
            Token.objects.filter(user=request.user).delete()
            logout(request)
        
        return Response({'detail': 'Successfully logged out.'})
    
    @action(detail=False, methods=['get'])
    def me(self, request):
        """Get current user profile"""
        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
    @action(detail=False, methods=['put', 'patch'])
    def update_profile(self, request):
        """Update current user profile"""
        serializer = UserProfileSerializer(
            request.user.profile,
            data=request.data,
            partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def change_password(self, request):
        """Change user password"""
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            
            # Check old password
            if not user.check_password(serializer.data.get('old_password')):
                return Response(
                    {'old_password': 'Wrong password.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Set new password
            user.set_password(serializer.data.get('new_password'))
            user.save()
            
            # Log activity
            UserActivity.objects.create(
                user=user,
                action=UserActivity.UPDATE,
                resource_type='password',
                description="Password changed",
                ip_address=self.get_client_ip(request)
            )
            
            return Response({'detail': 'Password updated successfully.'})
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['get'])
    def activities(self, request, pk=None):
        """Get user activity log"""
        user = self.get_object()
        activities = UserActivity.objects.filter(user=user)
        
        # Pagination
        page = self.paginate_queryset(activities)
        if page is not None:
            serializer = UserActivitySerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = UserActivitySerializer(activities, many=True)
        return Response(serializer.data)
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserActivityViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for UserActivity model (Read-only)"""
    queryset = UserActivity.objects.all()
    serializer_class = UserActivitySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Filter activities based on query parameters"""
        queryset = UserActivity.objects.select_related('user').all()
        
        # Filter by user
        user_id = self.request.query_params.get('user', None)
        if user_id:
            queryset = queryset.filter(user_id=user_id)
        
        # Filter by action
        action = self.request.query_params.get('action', None)
        if action:
            queryset = queryset.filter(action=action)
        
        # Filter by resource type
        resource_type = self.request.query_params.get('resource_type', None)
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)
        
        return queryset