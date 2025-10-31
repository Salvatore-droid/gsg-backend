from rest_framework import permissions

class ScanPermission(permissions.BasePermission):
    """
    Custom permission to handle scan operations
    """
    
    def has_permission(self, request, view):
        # Allow all authenticated users for basic operations
        if request.user and request.user.is_authenticated:
            return True
        return False
    
    def has_object_permission(self, request, view, obj):
        # Users can only access their own scan targets
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return True