import os

from flask import Flask, request
from werkzeug.security import generate_password_hash
from jetbase.db import get_db

def create_app(test_config=None):
  app = Flask(__name__, instance_relative_config=True)
  app.config.from_mapping(
    SECRET_KEY='dev',
    DATABASE=os.path.join(app.instance_path, 'jetbase.sqlite'),
  )

  if test_config is None:
    # load the instance config, if it exists, when not testing
    app.config.from_pyfile('config.py', silent=True)
  else:
    # load the test config if passed in
    app.config.from_mapping(test_config)

  # ensure the instance folder exists
  try:
    os.makedirs(app.instance_path)
  except OSError:
    pass

  @app.route('/users', methods=['GET', 'POST'])
  def users():
    if request.method == 'GET':
      db = get_db()
      error = None
      users = db.execute(
        'SELECT * FROM users'
      ).fetchall()

      return {
        "items": [
          {
            "id": 1,
            "first_name": "string",
            "last_name": "string",
            "email": "user@example.com",
            "role_id": 0
          }
        ],
        "count": 1
      }

    elif request.method == 'POST':
      data = request.get_json()

      first_name = data['first_name']
      last_name = data['last_name']
      email = data['email']
      password = data['password']

      db = get_db()
      error = None

      if not email:
        error = 'Email is required.'
      elif not password:
        error = 'Password is required.'
      elif db.execute(
        'SELECT id FROM users WHERE email = ?', (email,)
      ).fetchone() is not None:
        error = 'User {} is already registered.'.format(email)

      if error is None:
        user = db.execute(
          'INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)',
          (first_name, last_name, email, generate_password_hash(password))
        ).fetchone()
        db.commit()

        return {
          "id": user['id']
        }

      else:
        return {
          "error": error
        }

  @app.route('/users/current', methods=['GET'])
  def user_current():
    if request.method == 'GET':
      return {
        "id": 'current',
        "first_name": "string",
        "last_name": "string",
        "email": "user@example.com",
        "role_id": 0
      }

  @app.route('/users/<int:user_id>', methods=['DELETE', 'GET', 'PUT'])
  def user(user_id):
    if request.method == 'GET':
      db = get_db()
      user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
      return {
        "id": user['id'],
        "first_name": user['first_name'],
        "last_name": user['last_name'],
        "email": user['email']
      }

    elif request.method == 'PUT':
      return {
        "id": 1
      }

    elif request.method == 'DELETE':
      return {
        "id": 1
      }

  from . import db
  db.init_app(app)

  from . import auth
  app.register_blueprint(auth.bp)

  return app