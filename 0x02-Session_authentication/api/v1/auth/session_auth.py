#!/usr/bin/env python3
"""Session auth module
"""

from api.v1.auth.auth import Auth
from models.user import User
from uuid import uuid4


class SessionAuth(Auth):
    """Session auth class"""
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """Create a session"""
        if user_id is None:
            return None
        if type(user_id) is not str:
            return None
        session_id = str(uuid4())
        SessionAuth.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns a User ID based on a Session ID"""
        if session_id is None:
            return None
        if type(session_id) is not str:
            return None
        user_id = SessionAuth.user_id_by_session_id.get(session_id)
        return user_id

    def current_user(self, request=None):
        """returns a User instance based on a cookie value"""
        if request is None:
            return None
        session_cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_cookie)
        user = User.get(user_id)
        return user

    def destroy_session(self, request=None):
        """Destroys a session"""
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if not session_id:
            return False
        if not self.user_id_for_session_id(session_id):
            return False

        del self.user_id_by_session_id[session_id]
        return True
