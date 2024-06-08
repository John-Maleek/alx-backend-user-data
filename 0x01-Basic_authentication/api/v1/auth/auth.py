#!/usr/bin/env python3
""" Auth module
"""

from typing import List, TypeVar
from flask import request


class Auth():
    """Auth class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """requires authentication"""
        if path is None:
            return True
        if excluded_paths is None or excluded_paths is []:
            return True

        path = path.replace('/', '') if path.endswith('/') else path
        excluded_paths = [p.replace('/', '') if p.endswith('/') else p
                          for p in excluded_paths]
        for p in excluded_paths:
            if path.startswith(p.replace('*', '')):
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
        """method gets the current user"""
        return None
