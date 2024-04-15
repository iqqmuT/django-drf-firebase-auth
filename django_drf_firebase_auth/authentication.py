"""Firebase authentication for Django Rest Framework."""

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from firebase_admin import auth
from rest_framework import exceptions
from rest_framework.authentication import (
    BaseAuthentication,
    get_authorization_header,
)

import logging
logger = logging.getLogger(__name__)

User = get_user_model()

def get_setting(param, default_val):
    firebase_auth = getattr(settings, 'FIREBASE_AUTH', {})
    return firebase_auth.get(param, default_val)

class FirebaseAuthentication(BaseAuthentication):
    """
    Custom authentication class for Django Rest Framework which
    uses Firebase authentication.
    """

    keyword = 'Bearer'

    def authenticate(self, request):
        """
        Main method for authentication.
        """
        auth_val = get_authorization_header(request).split()

        if not auth_val or auth_val[0].lower() != self.keyword.lower().encode():
            return None

        if len(auth_val) == 1:
            msg = _('Invalid token header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth_val) > 2:
            msg = _('Invalid token header. Token string should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            token = auth_val[1].decode()
        except UnicodeError:
            msg = _('Invalid token header. Token string should not contain invalid characters.')
            raise exceptions.AuthenticationFailed(msg)

        return self.authenticate_token(token)

    def authenticate_token(self, token):
        try:
            payload = auth.verify_id_token(token)
        except (
            ValueError,
            auth.InvalidIdTokenError,
            auth.ExpiredIdTokenError,
            auth.RevokedIdTokenError,
            auth.CertificateFetchError,
            auth.UserDisabledError,
        ) as e:
            raise exceptions.AuthenticationFailed(str(e))

        if not payload['email_verified']:
            raise exceptions.AuthenticationFailed({
                'detail': _('User email not verified.'),
                'error': 'email-not-verified',
            })

        try:
            if get_setting('CREATE_NEW_USERS', False):
                user, created = self.get_or_create_user(payload)
            else:
                user = self.get_user(payload)
        except User.DoesNotExist:
            # user authenticated successfully but user record is missing from Django
            raise exceptions.AuthenticationFailed({
                'detail': _('User record does not exist.'),
                'error': 'user-not-found',
            })
        except User.MultipleObjectsReturned:
            raise exceptions.AuthenticationFailed({
                'detail': _('Multiple user records found.'),
                'error': 'multiple-users-found',
            })

        return (user, payload)

    def authenticate_header(self, request):
        return self.keyword

    def get_user(self, payload):
        return User.objects.get(email=payload['email'])

    def get_or_create_user(self, payload):
        logger.debug(f'get_or_create {payload}')
        return User.objects.get_or_create(email=payload['email'])
