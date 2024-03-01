from flask import request, Blueprint, jsonify
from config import JWT_IDENTITY_CLAIM
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt, \
    get_current_user
from marshmallow import ValidationError

from api.schemas.user import UserSchema, UserCreateSchema
from auth.helpers import add_token_to_database, revoke_token, is_token_revoked
from extensions import db, pwd_context, jwt
from models.user import User

auth_blueprint = Blueprint('auth', __name__, url_prefix='/auth')


@auth_blueprint.route("/register", methods=["POST"])
def register():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    schema = UserCreateSchema()
    user = schema.load(request.json)
    db.session.add(user)
    db.session.commit()

    schema = UserSchema()

    return {'message': "User created", "user": schema.dump(user)}, 201


@auth_blueprint.route("/login", methods=["POST"])
def login():
    if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400

    email = request.json.get('email')
    password = request.json.get('password')

    if not email or not password:
        return {'message': "Missing email or password"}, 400

    user = User.query.filter_by(email=email).first()
    if not user or not pwd_context.verify(password, user.password):
        return {'message': "Bad credentials"}, 400

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    add_token_to_database(access_token)
    add_token_to_database(refresh_token)
    return {'message': "login successful", "access_token": access_token, "refresh_token": refresh_token}, 201


@auth_blueprint.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    add_token_to_database(access_token)
    return {"access_token": access_token}, 200


@auth_blueprint.route("/revoke_access", methods=["DELETE"])
@jwt_required()
def revoke_access_token():
    jti = get_jwt()['jti']
    user_id = get_jwt_identity()
    revoke_token(jti, user_id)
    return {"message": "Token revoked"}, 200


@auth_blueprint.route("/revoke_refresh", methods=["DELETE"])
@jwt_required(refresh=True)
def revoke_refresh_token():
    jti = get_jwt()['jti']
    user = get_current_user()
    user_id = get_jwt_identity()
    revoke_token(jti, user_id)
    return {"message": "Refresh token revoked"}, 200


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_headers, jwt_payload):
    try:
        return is_token_revoked(jwt_payload)
    except Exception as error:
        return True


@jwt.user_lookup_loader
def load_user(jwt_headers, jwt_payload):
    user_id = jwt_payload[JWT_IDENTITY_CLAIM]
    return User.query.get(user_id)


@auth_blueprint.errorhandler(ValidationError)
def handle_marshmallow_error(e):
    return jsonify(e.messages), 400
