from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import User, UserProfile, Role, Permission, UserActivity


class PermissionSerializer(serializers.ModelSerializer):
    """Serializer for Permission model"""
    resource_display = serializers.CharField(source='get_resource_display', read_only=True)
    
    class Meta:
        model = Permission
        fields = [
            'id', 'role', 'resource', 'resource_display',
            'can_create', 'can_read', 'can_update', 'can_delete', 'can_approve',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for Role model"""
    permissions = PermissionSerializer(many=True, read_only=True)
    name_display = serializers.CharField(source='get_name_display', read_only=True)
    user_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Role
        fields = [
            'id', 'name', 'name_display', 'code', 'description',
            'is_active', 'permissions', 'user_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']
    
    def get_user_count(self, obj):
        return obj.users.count()


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for UserProfile model"""
    complete_address = serializers.CharField(source='get_complete_address', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'avatar', 'address', 'city', 'state', 'country', 'postal_code',
            'department', 'job_title', 'date_of_birth', 'bio',
            'complete_address', 'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    profile = UserProfileSerializer(read_only=True)
    role_detail = RoleSerializer(source='role', read_only=True)
    role_name = serializers.CharField(source='get_role_name', read_only=True)
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    password = serializers.CharField(write_only=True, required=False)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name', 'full_name',
            'employee_id', 'phone_number', 'role', 'role_name', 'role_detail',
            'is_active', 'is_staff', 'is_superuser', 'password',
            'profile', 'date_joined', 'last_login'
        ]
        read_only_fields = ['date_joined', 'last_login']
        extra_kwargs = {
            'password': {'write_only': True, 'min_length': 8}
        }
    
    def create(self, validated_data):
        """Create user with encrypted password"""
        password = validated_data.pop('password', None)
        user = User.objects.create(**validated_data)
        if password:
            user.set_password(password)
            user.save()
        
        # Create user profile automatically
        UserProfile.objects.create(user=user)
        
        return user
    
    def update(self, instance, validated_data):
        """Update user, handling password separately"""
        password = validated_data.pop('password', None)
        
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        
        if password:
            instance.set_password(password)
        
        instance.save()
        return instance


class UserListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for user lists"""
    role_name = serializers.CharField(source='get_role_name', read_only=True)
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'full_name', 'employee_id',
            'role_name', 'is_active', 'date_joined'
        ]


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration"""
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True, min_length=8)
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'first_name', 'last_name',
            'phone_number', 'password', 'password_confirm'
        ]
    
    def validate(self, data):
        """Validate that passwords match"""
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return data
    
    def create(self, validated_data):
        """Create new user"""
        validated_data.pop('password_confirm')
        password = validated_data.pop('password')
        
        user = User.objects.create(**validated_data)
        user.set_password(password)
        user.save()
        
        # Create user profile
        UserProfile.objects.create(user=user)
        
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login"""
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    
    def validate(self, data):
        """Validate user credentials"""
        username = data.get('username')
        password = data.get('password')
        
        if username and password:
            user = authenticate(username=username, password=password)
            
            if user:
                if not user.is_active:
                    raise serializers.ValidationError("User account is disabled.")
                data['user'] = user
            else:
                raise serializers.ValidationError("Unable to log in with provided credentials.")
        else:
            raise serializers.ValidationError("Must include 'username' and 'password'.")
        
        return data


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for password change"""
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(required=True, write_only=True, min_length=8)
    new_password_confirm = serializers.CharField(required=True, write_only=True, min_length=8)
    
    def validate(self, data):
        """Validate password change"""
        if data['new_password'] != data['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "New passwords do not match."})
        return data


class UserActivitySerializer(serializers.ModelSerializer):
    """Serializer for UserActivity model"""
    user_detail = UserListSerializer(source='user', read_only=True)
    action_display = serializers.CharField(source='get_action_display', read_only=True)
    
    class Meta:
        model = UserActivity
        fields = [
            'id', 'user', 'user_detail', 'action', 'action_display',
            'resource_type', 'resource_id', 'description',
            'ip_address', 'user_agent', 'timestamp'
        ]
        read_only_fields = ['timestamp']