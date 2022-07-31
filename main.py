import json
from flask import Flask, request, jsonify, g, abort
from flask_mongoengine import MongoEngine, Document
from flask_httpauth import HTTPBasicAuth
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import time

app = Flask(__name__)
auth = HTTPBasicAuth()

app.config["MONGODB_HOST"] = "mongodb://<username>:<password>@<host-name>:27017/?ssl=true&ssl_cert_reqs=CERT_REQUIRED&ssl_ca_certs=./cert.crt&authSource=admin"

app.secret_key = "hshdhadhashd"
db = MongoEngine()
db.init_app(app)


class User(Document):
    __tablename__ = "user"
    username = db.StringField(max_length=32, required=True, unique=True)
    password_hash = db.StringField(max_length=128)

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode({"id": str(self.id), "exp": time.time() + expires_in},
                          app.config['SECRET_KEY'], algorithm="HS256")

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=["HS256"])
        except:
            return

        return User.objects(id=data["id"]).first()


class Quote(Document):
    __tablename__ = "quote"
    author = db.ReferenceField(User)
    text = db.StringField(max_length=500, required=True)
    date_created = db.DateTimeField(auto_add_now=True)


def validate_username_password(username, password):
    if username is None or password is None:
        abort(400)
    if len(User.objects(username=username)) != 0:
        abort(400)


def validate_quote_ownership(quote_id, user_id):
    quote = Quote.objects(id=quote_id).first()

    if not quote:
        return False

    return quote.author.id == user_id


@auth.verify_password
def verify_password(username, password):
    user = None
    try:
        token = request.headers["Authorization"].split(" ")[1]
        user = User.verify_auth_token(token)
    except:
        pass

    if not user:
        user = User.objects(username=username).first()
        if not user or not user.verify_password(password):
            return False

    g.user = user
    return True


@app.route("/token")
@auth.login_required
def get_token():
    token = g.user.generate_auth_token()
    return jsonify({"token": token, "duration": 600})


@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    validate_username_password(username, password)

    user = User(username=username)
    user.hash_password(password)
    user.save()

    return jsonify({"user": user}), 201


@app.route("/create-quote", methods=["POST"])
@auth.login_required
def create_quote():
    text = request.json.get("text")

    if not text:
        abort(400)

    quote = Quote(text=text, author=g.user)
    quote.save()

    return jsonify({"quote": quote}), 201


@app.route("/get-all-quotes")
@auth.login_required
def get_all_quotes():
    quotes = Quote.objects()
    return jsonify({"quotes": quotes}), 200


@app.route("/get-my-quotes")
@auth.login_required
def get_user_quotes():
    user_id = g.user.id
    quotes = Quote.objects(author=user_id)

    return jsonify({"quotes": quotes}), 200


@app.route("/update-quote", methods=["PUT"])
@auth.login_required
def update_quote():
    _id = request.json.get("id")

    if not validate_quote_ownership(_id, g.user.id):
        abort(400)

    quote = Quote.objects(id=_id).first()
    new_text = request.json.get("text")

    if not quote or not new_text:
        abort(400)

    quote.text = new_text
    quote.save()

    return jsonify({"quote": quote}), 200


@app.route("/delete-quote", methods=["DELETE"])
@auth.login_required
def delete_quote():
    _id = request.json.get("id")

    if not validate_quote_ownership(_id, g.user.id):
        abort(400)

    quote = Quote.objects(id=_id).first()

    if not quote:
        abort(400)

    quote.delete()

    return jsonify({"status": "deleted successfully"}), 200


if __name__ == "__main__":
    app.run(port=8080, debug=True)
