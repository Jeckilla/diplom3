from rest_framework.permissions import BasePermission


class IsOwnerOrReadOnly(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method == 'GET':
            return True
        return request.user == obj.user


class IsOwner(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user == obj.user:
            return True
        else:
            return False


class IsShop(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.METHOD == 'GET':
            return True
        return request.user == obj.user

    def has_permission(self, request, view):
        if request.user.type == 'shop':
            return True
        return False
