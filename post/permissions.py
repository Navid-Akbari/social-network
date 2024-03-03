from rest_framework import permissions

class IsOwnerOrAdmin(permissions.BasePermission):

    message = 'User does not have permission to access this object.'
    code = 'object_access_denied'

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        if request.user.is_superuser or request.user.is_staff:
            return True

        return obj.user == request.user
