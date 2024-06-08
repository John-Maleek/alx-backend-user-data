#!/usr/bin/env python3
""" Basic auth module
"""


from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """Basic auth class"""
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """returns the Base64 part of the
        Authorization header for a Basic Authentication
        """
        if authorization_header is None:
            return None
        if type(authorization_header) is str:
            str_list = authorization_header.split(' ')
            if len(str_list) == 1 or str_list[0] != 'Basic':
                return None
            else:
                return str_list[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64
        string base64_authorization_header
        """
        if base64_authorization_header is None:
            return None
        if type(base64_authorization_header) is str:
            b64_str = base64_authorization_header
            try:
                if base64.b64decode(b64_str):
                    return base64.b64decode(b64_str).decode('utf-8')
            except Exception:
                return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> (str, str):
        """returns the user email and password
        from the Base64 decoded value.
        """
        header_str = decoded_base64_authorization_header
        if type(header_str) is str:
            if ':' not in header_str:
                return (None, None)
            else:
                credentials = header_str.split(':')
                return (credentials[0], ''.join(credentials[1:]))
        else:
            return (None, None)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """returns the User instance based on his"""
        if user_email is None or user_pwd is None:
            return None
        if type(user_email) is not str or type(user_pwd) is not str:
            return None
        try:
            users = User.search({'email': user_email})
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """retrieves the User instance for a request"""
        auth_header = self.authorization_header(request)
        b64Header = self.extract_base64_authorization_header(auth_header)
        decoded = self.decode_base64_authorization_header(b64Header)
        credentials = self.extract_user_credentials(decoded)
        user = self.user_object_from_credentials(
            credentials[0], credentials[1])
        return user
