from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User, UserProfile, Role, Permission, UserActivity


class UserProfileInline(admin.StackedInline):
    """Inline admin for UserProfile"""
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'
    fields = (
        'avatar', 'department', 'job_title', 'date_of_birth',
        'address', 'city', 'state', 'country', 'postal_code', 'bio'
    )


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom User Admin"""
    inlines = (UserProfileInline,)
    
    list_display = (
        'username', 'email', 'first_name', 'last_name',
        'role', 'employee_id', 'is_active', 'is_staff', 'date_joined'
    )
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'role', 'date_joined')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'employee_id')
    ordering = ('-date_joined',)
    
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal Info', {
            'fields': ('first_name', 'last_name', 'email', 'phone_number', 'employee_id')
        }),
        ('Role & Permissions', {
            'fields': ('role', 'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')
        }),
        ('Important Dates', {
            'fields': ('last_login', 'date_joined')
        }),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (
                'username', 'email', 'password1', 'password2',
                'first_name', 'last_name', 'role', 'employee_id',
                'phone_number', 'is_active', 'is_staff'
            ),
        }),
    )


class PermissionInline(admin.TabularInline):
    """Inline admin for Permissions"""
    model = Permission
    extra = 1
    fields = ('resource', 'can_create', 'can_read', 'can_update', 'can_delete', 'can_approve')


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    """Role Admin"""
    inlines = (PermissionInline,)
    
    list_display = ('name', 'code', 'is_active', 'user_count', 'created_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'code', 'description')
    ordering = ('name',)
    
    fieldsets = (
        (None, {
            'fields': ('name', 'code', 'description', 'is_active')
        }),
    )
    
    def user_count(self, obj):
        """Display number of users with this role"""
        return obj.users.count()
    user_count.short_description = 'Users'


@admin.register(Permission)
class PermissionAdmin(admin.ModelAdmin):
    """Permission Admin"""
    list_display = (
        'role', 'resource', 'can_create', 'can_read',
        'can_update', 'can_delete', 'can_approve'
    )
    list_filter = ('role', 'resource', 'can_create', 'can_read', 'can_update', 'can_delete')
    search_fields = ('role__name', 'resource')
    ordering = ('role', 'resource')
    
    fieldsets = (
        (None, {
            'fields': ('role', 'resource')
        }),
        ('Permissions', {
            'fields': ('can_create', 'can_read', 'can_update', 'can_delete', 'can_approve')
        }),
    )


@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    """User Activity Admin (Read-only)"""
    list_display = (
        'user', 'action', 'resource_type', 'resource_id',
        'ip_address', 'timestamp'
    )
    list_filter = ('action', 'resource_type', 'timestamp')
    search_fields = ('user__username', 'user__email', 'description', 'ip_address')
    ordering = ('-timestamp',)
    readonly_fields = (
        'user', 'action', 'resource_type', 'resource_id',
        'description', 'ip_address', 'user_agent', 'timestamp'
    )
    
    def has_add_permission(self, request):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    """UserProfile Admin (optional, since it's already inline)"""
    list_display = ('user', 'department', 'job_title', 'city', 'country')
    list_filter = ('department', 'country', 'city')
    search_fields = ('user__username', 'user__email', 'department', 'job_title')
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Professional Info', {
            'fields': ('department', 'job_title', 'employee_id')
        }),
        ('Personal Info', {
            'fields': ('avatar', 'date_of_birth', 'bio')
        }),
        ('Address', {
            'fields': ('address', 'city', 'state', 'country', 'postal_code')
        }),
    )
    
    def employee_id(self, obj):
        return obj.user.employee_id
    employee_id.short_description = 'Employee ID'