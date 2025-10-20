from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from functools import wraps
import os, hashlib
from PIL import Image

# ---------- App & Config ----------
app = Flask(__name__, static_folder="static", static_url_path="/static")
app.secret_key = "change_this_secret"  # ⚠️ change-moi avant rendu
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///bi_users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Uploads
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_EXTS = {"png", "jpg", "jpeg", "webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

db = SQLAlchemy(app)

# ---------- Modèle ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'FIFA' | 'Fed' | 'Staff'
    # Profil
    full_name = db.Column(db.String(120))
    country = db.Column(db.String(80))
    favorite_team = db.Column(db.String(80))
    bio = db.Column(db.Text)
    avatar_filename = db.Column(db.String(255))

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)

    def gravatar_url(self, size=160, default="mp"):
        email_clean = (self.email or "").strip().lower().encode("utf-8")
        digest = hashlib.md5(email_clean).hexdigest()
        return f"https://www.gravatar.com/avatar/{digest}?s={size}&d={default}"

    def avatar_url(self):
        if self.avatar_filename:
            return url_for("static", filename=f"uploads/{self.avatar_filename}")
        return self.gravatar_url()

# ---------- Helpers ----------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTS

def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper

# rendre current_user dispo dans tous les templates
@app.context_processor
def inject_current_user():
    u = None
    if session.get("user_id"):
        u = User.query.get(session["user_id"])
    return {"current_user": u}

@app.errorhandler(RequestEntityTooLarge)
def too_large(e):
    return render_template("error.html", message="Fichier trop volumineux (max 5 MB)."), 413

# ---------- Routes ----------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "")

        full_name = request.form.get("full_name")
        country = request.form.get("country")
        favorite_team = request.form.get("favorite_team")
        bio = request.form.get("bio")
        avatar_file = request.files.get("avatar")

        if not email or not password or role not in ("FIFA", "Fed", "Staff"):
            return render_template("signup.html", error="Champs invalides.",
                                   email=email, role=role, full_name=full_name,
                                   country=country, favorite_team=favorite_team, bio=bio)

        if User.query.filter_by(email=email).first():
            return render_template("signup.html", error="Cet email existe déjà.",
                                   email=email, role=role, full_name=full_name,
                                   country=country, favorite_team=favorite_team, bio=bio)

        user = User(email=email, role=role,
                    full_name=full_name, country=country,
                    favorite_team=favorite_team, bio=bio)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()  # pour obtenir user.id

        # Upload avatar si fourni
        if avatar_file and avatar_file.filename and allowed_file(avatar_file.filename):
            filename = secure_filename(avatar_file.filename)
            ext = filename.rsplit(".", 1)[1].lower()
            stored = f"user_{user.id}.{ext}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
            avatar_file.save(path)
            try:
                with Image.open(path) as img:
                    img.verify()  # lève une Exception si non-image
            except Exception:
                os.remove(path)
                return render_template("signup.html", error="Le fichier n'est pas une image valide.",
                                       email=email, role=role, full_name=full_name,
                                       country=country, favorite_team=favorite_team, bio=bio)
            user.avatar_filename = stored
            db.session.commit()

        # ➜ redirige vers la connexion (pas de login auto)
        return redirect(url_for("login"))

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            return render_template("login.html", error="Identifiants invalides.", email=email)
        session.update({"user_id": user.id, "email": user.email, "role": user.role})
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ----- Profil -----
@app.route("/me")
@login_required
def profile_view():
    user = User.query.get(session["user_id"])
    return render_template("profile.html", user=user)

@app.route("/me/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    user = User.query.get(session["user_id"])
    if request.method == "POST":
        user.full_name = request.form.get("full_name")
        user.country = request.form.get("country")
        user.favorite_team = request.form.get("favorite_team")
        user.bio = request.form.get("bio")

        avatar_file = request.files.get("avatar")
        if avatar_file and avatar_file.filename and allowed_file(avatar_file.filename):
            filename = secure_filename(avatar_file.filename)
            ext = filename.rsplit(".", 1)[1].lower()
            stored = f"user_{user.id}.{ext}"
            path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
            avatar_file.save(path)
            try:
                with Image.open(path) as img:
                    img.verify()
            except Exception:
                os.remove(path)
                return render_template("profile_edit.html", user=user, error="Image invalide.")
            user.avatar_filename = stored

        db.session.commit()
        return redirect(url_for("profile_view"))

    return render_template("profile_edit.html", user=user)

# ---------- Dashboards par rôle ----------
@app.route("/dashboard")
@login_required
def dashboard():
    print(session)
    return render_template("dashboard.html", session=session)

# ---------- Predictions ----------
@app.route("/predictions")
@login_required
def predictions():
    return render_template("predictions.html")

# ---------- Démarrage ----------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5001)