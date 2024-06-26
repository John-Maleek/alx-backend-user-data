#!/usr/bin/env python3
""" Module of Session Auth views
"""
from os import getenv
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User


@app_views.route('/auth_session/login',
                 methods=['POST'], strict_slashes=False)
def login():
    """ POST /auth_session/login
    Return:
        - Dictionary representation of the User
    """
    email = request.form.get('email')
    password = request.form.get("password")
    if not email:
        return (jsonify({"error": "email missing"}), 400)
    if not password:
        return (jsonify({"error": "password missing"}), 400)

    user = User.search({"email": email})
    if not user:
        return (jsonify({"error": "no user found for this email"}), 404)

    user = user[0]
    pwd = user.is_valid_password(password)
    if not pwd:
        return (jsonify({"error": "wrong password"}), 401)

    from api.v1.app import auth
    session_id = auth.create_session(user.id)
    user_dict = jsonify(user.to_json())
    user_dict.set_cookie(getenv('SESSION_NAME'), session_id)
    return user_dict


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout() -> str:
    """ Deleting the Session ID contains in the request as cookie """
    """ DELETE /auth_session/login
    Return:
        - Dictionary representation of the User
    """
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return (jsonify({}), 200)
