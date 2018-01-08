import time

from jwt import DecodeError, ExpiredSignature

from ..exceptions import AuthTokenError
from .oauth import BaseOAuth2

import os

"""
OAuth2 Backend to work with microsoft graph.
"""


class TolaOAuth2(BaseOAuth2):
    name = 'tola'
    SCOPE_SEPARATOR = ' '
    AUTHORIZATION_URL = (os.getenv('TOLA_ACTIVITY_API_URL', '') +
                         '/oauth/authorize')
    ACCESS_TOKEN_URL = (os.getenv('TOLA_ACTIVITY_API_URL', '') +
                        '/oauth/token/')

    ACCESS_TOKEN_METHOD = 'POST'
    REDIRECT_STATE = False
    DEFAULT_SCOPE = ['read','write']

    def setting(self, name, default=None):
        s = self.strategy.setting(name, default=default, backend=self)
        return s

    def get_redirect_uri(self, state=None):
        if self.setting("REDIRECT_URL") != None:
            print("Redirect to custom url")
            return self.setting("REDIRECT_URL")
        else:
            return super(BaseOAuth2, self).get_redirect_uri(state=state)

    def get_user_id(self, details, response):
        """Use user account id as unique id"""
        return response.get('id')

    def get_user_details(self, response):
        """Return user details from Tola Activity account"""
        return {'username': response.get('username', ''),
                'email': response.get('email'),
                'fullname': response.get('first_name', '')+' '+response.get('last_name', ''),
                'first_name': response.get('first_name', ''),
                'last_name': response.get('last_name', '')}

    def user_data(self, access_token, *args, **kwargs):
        try:
            resp = self.get_json(
                os.getenv('TOLA_ACTIVITY_API_URL', '') + '/oauthuser',
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Accept': 'application/json',
                    'Authorization': 'Bearer '+access_token
                },
                method='GET'
            )

        except (DecodeError, ExpiredSignature) as de:
            raise AuthTokenError(self, de)

        return resp