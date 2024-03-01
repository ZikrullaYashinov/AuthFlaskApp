import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

FLASK_RUN_HOST = os.environ.get('FLASK_RUN_HOST', 'localhost')
FLASK_RUN_PORT = os.environ.get('FLASK_RUN_PORT', 9000)
FLASK_RUN_DEBUG = os.environ.get('FLASK_RUN_DEBUG', False)
SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
JWT_TOKEN_LOCATION = ["headers"]
JWT_IDENTITY_CLAIM = "user_id"
JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=5)
