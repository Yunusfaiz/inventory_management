from django.contrib.auth.models import AbstractUser
from django.db import models
from django.core.validators import RegexValidator


class Role(models.Model):
    """Role model for user role-based access control"""
    
    # Role choices
    ADMIN = 'ADMIN'
    MANAGER = 'MANAGER'
    WAREHOUSE_STAFF = 'WAREHOUSE_STAFF'
    SALES = 'SALES'
    PURCHASING = 'PURCHASING'
    ACCOUNTANT = 'ACCOUNTANT'
    VIEWER = 'VIEWER'
    
    ROLE_CHOICES = [
        (ADMIN, 'Administrator'),
        (MANAGER, 'Manager'),
        (WAREHOUSE_STAFF, 'Warehouse Staff'),
        (SALES, 'Sales'),
        (PURCHASING, 'Purchasing'),
        (ACCOUNTANT, 'Accountant'),
        (VIEWER, 'Viewer'),
    ]
    
    name = models.CharField(max_length=50, choices=ROLE_CHOICES, unique=True)
    code = models.CharField(max_length=20, unique=True)
    description = models.TextField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'roles'
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'
        ordering = ['name']
    
    def __str__(self):
        return self.get_name_display()
    
    def get_permissions_summary(self):
        """Returns a summary of all permissions for this role"""
        permissions = self.permissions.all()
        return {
            perm.resource: {
                'create': perm.can_create,
                'read': perm.can_read,
                'update': perm.can_update,
                'delete': perm.can_delete,
                'approve': perm.can_approve,
            }
            for perm in permissions
        }


class User(AbstractUser):
    """Custom User model extending Django's AbstractUser"""
    
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    
    email = models.EmailField(unique=True)
    role = models.ForeignKey(
        Role,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='users'
    )
    employee_id = models.CharField(max_length=50, unique=True, null=True, blank=True)
    phone_number = models.CharField(validators=[phone_regex], max_length=17, null=True, blank=True)
    
    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['-date_joined']
    
    def __str__(self):
        return self.get_full_name() or self.username
    
    def get_full_name(self):
        """Returns the user's full name"""
        full_name = f"{self.first_name} {self.last_name}".strip()
        return full_name if full_name else self.username
    
    def get_role_name(self):
        """Returns the user's role name or 'No Role'"""
        return self.role.get_name_display() if self.role else 'No Role'
    
    def has_permission(self, resource, action):
        """Check if user has specific permission for a resource and action"""
        if self.is_superuser:
            return True
        
        if not self.role:
            return False
        
        try:
            permission = self.role.permissions.get(resource=resource)
            return getattr(permission, f'can_{action}', False)
        except Permission.DoesNotExist:
            return False


class UserProfile(models.Model):
    """Extended profile information for users"""
    
    user = models.OneToOneField(
        User,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name='profile'
    )
    avatar = models.ImageField(upload_to='avatars/', null=True, blank=True)
    address = models.TextField(null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    state = models.CharField(max_length=100, null=True, blank=True)
    country = models.CharField(max_length=100, null=True, blank=True)
    postal_code = models.CharField(max_length=20, null=True, blank=True)
    department = models.CharField(max_length=100, null=True, blank=True)
    job_title = models.CharField(max_length=100, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    bio = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'
    
    def __str__(self):
        return f"{self.user.get_full_name()}'s Profile"
    
    def get_complete_address(self):
        """Returns formatted complete address"""
        address_parts = [
            self.address,
            self.city,
            self.state,
            self.postal_code,
            self.country
        ]
        return ', '.join(filter(None, address_parts))


class Permission(models.Model):
    """Permission model for granular access control"""
    
    # Resource choices (can be extended)
    PRODUCTS = 'products'
    INVENTORY = 'inventory'
    ORDERS = 'orders'
    PURCHASE_ORDERS = 'purchase_orders'
    CUSTOMERS = 'customers'
    SUPPLIERS = 'suppliers'
    REPORTS = 'reports'
    USERS = 'users'
    
    RESOURCE_CHOICES = [
        (PRODUCTS, 'Products'),
        (INVENTORY, 'Inventory'),
        (ORDERS, 'Orders'),
        (PURCHASE_ORDERS, 'Purchase Orders'),
        (CUSTOMERS, 'Customers'),
        (SUPPLIERS, 'Suppliers'),
        (REPORTS, 'Reports'),
        (USERS, 'Users'),
    ]
    
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name='permissions'
    )
    resource = models.CharField(max_length=100, choices=RESOURCE_CHOICES)
    can_create = models.BooleanField(default=False)
    can_read = models.BooleanField(default=False)
    can_update = models.BooleanField(default=False)
    can_delete = models.BooleanField(default=False)
    can_approve = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'permissions'
        verbose_name = 'Permission'
        verbose_name_plural = 'Permissions'
        unique_together = ['role', 'resource']
        ordering = ['role', 'resource']
    
    def __str__(self):
        return f"{self.role.get_name_display()} - {self.get_resource_display()}"
    
    def has_any_permission(self):
        """Check if at least one permission is granted"""
        return any([
            self.can_create,
            self.can_read,
            self.can_update,
            self.can_delete,
            self.can_approve
        ])


class UserActivity(models.Model):
    """Track user activities for audit trail"""
    
    # Action choices
    LOGIN = 'LOGIN'
    LOGOUT = 'LOGOUT'
    CREATE = 'CREATE'
    UPDATE = 'UPDATE'
    DELETE = 'DELETE'
    VIEW = 'VIEW'
    APPROVE = 'APPROVE'
    REJECT = 'REJECT'
    
    ACTION_CHOICES = [
        (LOGIN, 'Login'),
        (LOGOUT, 'Logout'),
        (CREATE, 'Create'),
        (UPDATE, 'Update'),
        (DELETE, 'Delete'),
        (VIEW, 'View'),
        (APPROVE, 'Approve'),
        (REJECT, 'Reject'),
    ]
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='activities'
    )
    action = models.CharField(max_length=50, choices=ACTION_CHOICES)
    resource_type = models.CharField(max_length=100, null=True, blank=True)
    resource_id = models.IntegerField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'user_activities'
        verbose_name = 'User Activity'
        verbose_name_plural = 'User Activities'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['-timestamp']),
            models.Index(fields=['user', '-timestamp']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.get_action_display()} - {self.timestamp}"