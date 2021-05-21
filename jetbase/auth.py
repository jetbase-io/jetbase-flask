import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from jetbase.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/login', methods=['POST'])
def login():
  if request.method == 'POST':
    email = request.form['email']
    password = request.form['password']
    db = get_db()
    error = None
    user = db.execute(
      'SELECT * FROM user WHERE email = ?', (email,)
    ).fetchone()

    if user is None:
      error = 'Incorrect email.'
    elif not check_password_hash(user['password'], password):
      error = 'Incorrect password.'

    if error is None:
      return {
        "token": user["id"],
        "rate_limit": 3600,
        "expires_after": "2021-05-09T13:56:17.085Z"
      }

    else:
      return {
        "error": true
      }

@bp.route('/logout', methods=['DELETE'])
def logout():
  if request.method == 'DELETE':
    return {}