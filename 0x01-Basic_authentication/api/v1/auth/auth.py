#!/usr/bin/env python3
""" Auth module
"""

from typing import List, TypeVar
from flask import request


class Auth():
    """Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        if path is None:
            return True
        if excluded_paths is None or excluded_paths is []:
            return True

        path = path if path.endswith('/') else '{}/'.format(path)
        excluded_paths = [p if p.endswith('/') else '{}/'.format(p)
                          for p in excluded_paths]
        if path in excluded_paths:
            return False
        else:
            return True

    def authorization_header(self, request=None) -> str:
        """method to validate requests"""
        if request is None:
            return None
        else:
            return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):  # type: ignore
        return None
