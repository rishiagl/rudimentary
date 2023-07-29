import functools, jwt, os

from flask import (
    Blueprint, g, redirect, render_template, request, session, url_for, make_response, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash

from rudy.db import get_db
from rudy.utils import Json_Response


bp = Blueprint('auth_jwt', __name__, url_prefix='/auth/jwt')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        j: jsonify = None
        try:
            j = request.get_json()
        except:
            resp = Json_Response()
            resp.status = 415
            resp.error_message = "request body must be json"
            return resp.response()
        
        username = j['username']
        password = j['password']
        db = get_db()
        error = None

        if not username:
            error = 'username is required.'
        elif not password:
            error = 'password is required.'

        if error is None:
            try:
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"user {username} is already registered."
            else:
                resp = Json_Response()
                resp.status = 200
                resp.message = "user Successfully Registered, Please Login"
                return resp.response()
            
        resp = Json_Response()
        resp.status = 404
        resp.error_message = error
        return resp.response()

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        j: jsonify = None
        try:
            j = request.get_json()
        except:
            resp = Json_Response()
            resp.status = 415
            resp.error_message = "request body must be json"
            return resp.response()
        
        username = j['username']
        password = j['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'user not found'
            resp = Json_Response()
            resp.status = 404
            resp.error_message = error
            return resp.response()
        elif not check_password_hash(user['password'], password):
            error = "password does not match"
            resp = Json_Response()
            resp.status = 401
            resp.error_message = error
            return resp.response()

        if error is None:
            access_token = jwt.encode({"user_id": user['id']}, os.environ.get("SECRET_KEY"), algorithm="HS256")
            resp = Json_Response()
            resp.status = 200
            resp.message = "user Logged in Successfully"
            resp.addHeader("access_token", access_token)
            return resp.response()
        
        error = "Unidentified Error"
        resp = Json_Response()
        resp.status = 500
        resp.error_message = error
        resp.addHeader("access_token", access_token)
        return resp.response()

    return render_template('auth/login.html')

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        token = request.args.get('access_token')
        if not token:
            resp = Json_Response()
            resp.status = 401
            resp.error_message = "access_token is required"
            return resp.response()
        try:
            j = jwt.decode(token, os.environ.get("SECRET_KEY"), algorithms="HS256")
            g.userid = j["user_id"]
        except:
            resp = Json_Response()
            resp.status = 401
            resp.error_message = "access_token is invalid"
            return resp.response()

        return view(**kwargs)

    return wrapped_view

