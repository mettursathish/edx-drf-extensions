""" Permission classes. """
from rest_framework.permissions import BasePermission
from provider.oauth2.models import AccessToken as DOPAccessToken
from edx_rest_framework_extensions.utils import jwt_decode_handler

class IsSuperuser(BasePermission):
    """ Allows access only to superusers. """

    def has_permission(self, request, view):
        return request.user and request.user.is_superuser

class JWTRestrictedApplicationPermission(BasePermission):
    """
    This permission class will inspect a request which contains an
    OAuth2 access_token. The following business logic is applied:
    1) Is the OAuth2 token passed in a legacy django-oauth-provider (DOP) token, if so
       all applications connecting via DOP reflect trusted internal applications
    2) Is the access_token associated with a RestrictedApplication? If not,
       the caller is viewed as a trusted application and the permission check is passed
    3) If the access_token is associated with a RestrictedApplication, then:
        2a) Get the 'scopes' from the access_token and inspect the passed in 'view'
        2b) Inspect the view object for a 'required_scopes' attribute on the view
        2c) If there is no 'required_scopes', then FAIL THE REQUEST, since the
            view has not declared how to allow RestrictedApplication to access it
        2d) If there is a 'required_scopes' attribute on the view object then make
            sure that the access_token has that scope on it
        2e) If access_token does not contain the 'required_scopes' then fail the request
        2f) If all above checks succees, pass the permissions check
    """
    def _token_filters(self, token):
        # get filters list from jwt token and return dict
        if jwt_decode_handler(token).has_key('filters'):
	    filters_list = jwt_decode_handler(token)['filters']
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

        # check to see if token is a DOP token
        # if so this represents a client which is implicitly trusted
        # (since it is an internal Open edX application)
        if isinstance(token, DOPAccessToken):
            return True
        
        if not float(jwt_decode_handler(token)['version']) <= 1.0:
            return False
        has_permission = super(JWTRestrictedApplicationPermission, self).has_permission(request, view)
        if has_permission:
            # Add a new attributes to the Django request which sets an 'content_org' and 'user' filters
            # which will be used by the view handlers for course filtering
            # based on the rights declared on the RestrictedApplication
            setattr(request, 'filters', self._token_filters(token))
        return has_permission
