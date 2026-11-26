
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import hashlib
import secrets
import hmac
import time

app = Flask(__name__)

app.secret_key = secrets.token_hex(32)

DATABASE = os.path.join(os.path.dirname(__file__), "users.db")

MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 60


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password):
    salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, 600000
    )

    return salt.hex() + ":" + hashed.hex()


def verify_password(password, stored_password):
    salt, stored_hash = stored_password.split(":")

    new_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(salt),
        600000
    )

    return hmac.compare_digest(new_hash.hex(), stored_hash)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not email or not password:
            return render_template(
                "register.html",
                message="Please fill in all fields."
            )

        if "@" not in email or "." not in email:
            return render_template(
                "register.html",
                message="Please enter a valid email address."
            )

        if len(password) < 8:
            return render_template(
                "register.html",
                message="Password must contain at least 8 characters."
            )

        hashed_password = hash_password(password)

        conn = get_db_connection()

        try:
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed_password)
            )

            conn.commit()
            message = "Registration successful! You can now log in."

        except sqlite3.IntegrityError:
            message = "Username or email already exists."

        finally:
            conn.close()

        return render_template("register.html", message=message)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()

        security = conn.execute(
            "SELECT failed_attempts, locked_until FROM login_security WHERE username = ?",
            (username,)
        ).fetchone()

        attempts = security["failed_attempts"] if security else 0
        locked_until = security["locked_until"] if security else 0

        if time.time() < locked_until:
            remaining = int(locked_until - time.time()) + 1
            conn.close()

            return render_template(
                "login.html",
                message=f"Account locked. Try again in {remaining} seconds."
            )

        if locked_until and time.time() >= locked_until:
            attempts = 0

        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if user and verify_password(password, user["password"]):

            conn.execute(
                "INSERT OR REPLACE INTO login_security VALUES (?, 0, 0)",
                (username,)
            )

            conn.commit()
            conn.close()

            session["username"] = username

            return redirect(url_for("dashboard"))

        attempts += 1

        if attempts >= MAX_ATTEMPTS:
            new_lock = time.time() + LOCKOUT_DURATION

            conn.execute(
                "INSERT OR REPLACE INTO login_security VALUES (?, ?, ?)",
                (username, attempts, new_lock)
            )

            message = "Too many failed attempts. Account locked for 60 seconds."

        else:
            conn.execute(
                "INSERT OR REPLACE INTO login_security VALUES (?, ?, 0)",
                (username, attempts)
            )

            message = f"Incorrect username or password. {MAX_ATTEMPTS - attempts} attempts remaining."

        conn.commit()
        conn.close()

        return render_template("login.html", message=message)

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()

    user = conn.execute(
        "SELECT username, email, created_at FROM users WHERE username = ?",
        (session["username"],)
    ).fetchone()

    conn.close()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
