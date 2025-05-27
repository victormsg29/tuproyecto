import os
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from models import db, User

load_dotenv()

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///data.db")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "super-secret")
db.init_app(app)
jwt = JWTManager(app)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        email = data["email"]
        pw    = data["password"]
        ref   = data.get("ref", None)  # link de referido: /register?ref=123
        if User.query.filter_by(email=email).first():
            return "Email ya registrado", 400
        pw_hash = generate_password_hash(pw)
        user = User(email=email, password_hash=pw_hash, referido_por=ref)
        db.session.add(user)
        db.session.commit()
        token = create_access_token(identity=user.id)
        return jsonify(access_token=token), 200
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        user = User.query.filter_by(email=data["email"]).first()
        if not user or not check_password_hash(user.password_hash, data["password"]):
            return "Credenciales inválidas", 401
        token = create_access_token(identity=user.id)
        return jsonify(access_token=token), 200
    return render_template("login.html")

# Ruta ejemplo protegida
@app.route("/profile")
@jwt_required()
def profile():
    uid = get_jwt_identity()
    user = User.query.get(uid)
    return jsonify({
        "email": user.email,
        "wallet": user.wallet_addr,
        "balance": user.balance_usdt
    })

if __name__ == "__main__":
    app.run(port=5000)
