""" Permission classes. """
from rest_framework.permissions import BasePermission
from provider.oauth2.models import AccessToken as DOPAccessToken
from edx_rest_framework_extensions.utils import jwt_decode_handler
from oauth2_provider.ext.rest_framework.permissions import TokenHasScope


class IsSuperuser(BasePermission):
    """ Allows access only to superusers. """

    def has_permission(self, request, view):
        return request.user and request.user.is_superuser


class JWTRestrictedApplicationPermission(BasePermission):
    """
    The request is authenticated and has the required scopes and organization filters
    """

    def _token_filters(self, decoded_token):
        # get filters list from jwt token and return dict
        if 'filters' in decoded_token:
            filters_list = decoded_token['filters']
            filters = {}
            for each in filters_list:
                each = each.split(':')
                if each[0] in filters.keys():
                    filters[each[0]].append(each[1])
                else:
                    filters[each[0]] = [each[1]]
            return filters

    def has_permission(self, request, view):
        """
        Implement the business logic discussed above
        """

        token = request.auth
        decoded_token = jwt_decode_handler(token)
        # check to see if token is a DOP token
        # if so this represents a client which is implicitly trusted
        # (since it is an internal Open edX application)
        if isinstance(token, DOPAccessToken):
            return True

        if not float(decoded_token['version']) <= 1.0:
            return False

        if hasattr(view, 'required_scopes'):
            if not getattr(view, 'required_scopes')[0] in decoded_token['scopes']:
                return False

        has_permission = super(JWTRestrictedApplicationPermission, self).has_permission(request, view)

        if has_permission:
            setattr(request, 'oauth_scopes_filters', self._token_filters(decoded_token))

        return has_permission
