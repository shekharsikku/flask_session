from bcrypt import hashpw, gensalt, checkpw
from flask_marshmallow import Marshmallow
from flask import make_response, jsonify

# functions for generate password hash and check hash password

def generate_hashed(plain_password):
    return hashpw(plain_password.encode("utf-8"), gensalt()).decode()


def check_hashed(plain_password, hashed_password):
    return checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


# schema for validate response data

ma = Marshmallow()


class UserSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "email", "username", "date")


user_schema = UserSchema()
users_schema = UserSchema(many=True)


class LoginUserSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "email", "username", "password", "date")


login_user_schema = LoginUserSchema()

# Api response function

def api_response(message: str, code: int, data: any = None):
    success = True if code < 400 else False
    response = {"message": message, "success": success, "code": code}
    if data:
        response["data"] = data
    return make_response(jsonify(response), code)
