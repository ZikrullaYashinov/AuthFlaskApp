from flask import Flask
from auth.views import auth_blueprint
from api.views import blueprint
from config import FLASK_RUN_HOST, FLASK_RUN_PORT
from extensions import db, migrate, jwt

app = Flask(__name__)
app.register_blueprint(blueprint=blueprint)
app.register_blueprint(blueprint=auth_blueprint)
app.config.from_object('config')

db.init_app(app)
migrate.init_app(app, db)
jwt.init_app(app)

if __name__ == '__main__':
    app.run(host=FLASK_RUN_HOST, port=FLASK_RUN_PORT)
