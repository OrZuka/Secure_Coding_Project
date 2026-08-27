from __future__ import annotations

import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for


ROOT = Path(__file__).resolve().parent


def load_config() -> dict:
    return json.loads((ROOT / "config.json").read_text(encoding="utf-8"))


def password_digest(password: str, salt: bytes) -> str:
    return hmac.new(salt, password.encode("utf-8"), hashlib.sha256).hexdigest()


def make_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(32)
    return salt.hex(), password_digest(password, salt)


def matches_password(password: str, salt_hex: str, digest: str) -> bool:
    actual = password_digest(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(actual, digest)


def validate_password(password: str, cfg: dict) -> list[str]:
    policy = cfg["password"]
    errors = []
    if len(password) < int(policy["min_length"]):
        errors.append(f"Password must contain at least {policy['min_length']} characters.")
    if policy["require_uppercase"] and not re.search(r"[A-Z]", password):
        errors.append("Password must contain an uppercase letter.")
    if policy["require_lowercase"] and not re.search(r"[a-z]", password):
        errors.append("Password must contain a lowercase letter.")
    if policy["require_digit"] and not re.search(r"\d", password):
        errors.append("Password must contain a digit.")
    if policy["require_special"] and not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain a special character.")
    dictionary_path = ROOT / policy["dictionary_file"]
    blocked = {line.strip().lower() for line in dictionary_path.read_text(encoding="utf-8").splitlines() if line.strip()}
    if password.lower() in blocked:
        errors.append("Password appears in the configured password dictionary.")
    return errors


def create_app(version: str, db_path: Path | None = None) -> Flask:
    vulnerable = version == "vulnerable"
    version_dir = ROOT / f"{version}_version"
    cfg = load_config()
    app = Flask(
        __name__,
        template_folder=str(version_dir / "templates"),
        static_folder=str(version_dir / "static"),
    )
    app.secret_key = os.environ.get("COMMUNICATION_LTD_SECRET", secrets.token_hex(32))
    app.config.update(VERSION=version, VULNERABLE=vulnerable, DB_PATH=db_path or (version_dir / "communication_ltd.db"))

    @contextmanager
    def db():
        connection = sqlite3.connect(app.config["DB_PATH"])
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def init_db() -> None:
        with db() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    salt TEXT NOT NULL,
                    password_hmac TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    salt TEXT NOT NULL,
                    password_hmac TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS customers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT,
                    package_name TEXT,
                    sector TEXT,
                    created_by INTEGER,
                    FOREIGN KEY(created_by) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_sha1 TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                );
                """
            )

    init_db()

    def current_user():
        user_id = session.get("user_id")
        if not user_id:
            return None
        with db() as con:
            return con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    def write_reset_email(email: str, token: str) -> None:
        outbox = version_dir / cfg["mail"]["outbox_file"]
        with outbox.open("a", encoding="utf-8") as handle:
            handle.write(f"To: {email}\nCommunication_LTD password reset value: {token}\n\n")

    @app.context_processor
    def template_context():
        return {"current_user": current_user(), "version": version, "vulnerable": vulnerable}

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            errors = validate_password(password, cfg)
            if not username or not email:
                errors.append("Username and email are required.")
            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template("register.html")
            salt, digest = make_password(password)
            try:
                with db() as con:
                    if vulnerable:
                        # Unsafe on purpose so I can demonstrate SQL injection in the lab.
                        sql = ("INSERT INTO users(username,email,salt,password_hmac) VALUES ('" + username + "','" + email + "','" + salt + "','" + digest + "')")
                        cur = con.execute(sql)
                    else:
                        cur = con.execute(
                            "INSERT INTO users(username,email,salt,password_hmac) VALUES (?,?,?,?)",
                            (username, email, salt, digest),
                        )
                    con.execute(
                        "INSERT INTO password_history(user_id,salt,password_hmac,created_at) VALUES (?,?,?,?)",
                        (cur.lastrowid, salt, digest, datetime.now(timezone.utc).isoformat()),
                    )
                safe_name = username if vulnerable else html.escape(username)
                flash(f"User {safe_name} was registered.", "success")
                return redirect(url_for("login"))
            except sqlite3.Error as exc:
                flash(f"Registration failed: {exc}", "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            try:
                with db() as con:
                    if vulnerable:
                        # Same unsafe query style as the example we covered in class.
                        user = con.execute("SELECT * FROM users WHERE username = '" + username + "'").fetchone()
                    else:
                        user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
                    if not user:
                        flash("User does not exist.", "error")
                    elif user["locked"]:
                        flash("Account is locked after the configured number of attempts.", "error")
                    elif matches_password(password, user["salt"], user["password_hmac"]):
                        con.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
                        session.clear()
                        session["user_id"] = user["id"]
                        return redirect(url_for("system"))
                    else:
                        attempts = user["failed_attempts"] + 1
                        locked = int(attempts >= int(cfg["login"]["max_attempts"]))
                        con.execute("UPDATE users SET failed_attempts = ?, locked = ? WHERE id = ?", (attempts, locked, user["id"]))
                        flash("Incorrect password." if not locked else "Account locked after three failed attempts.", "error")
            except sqlite3.Error as exc:
                flash(f"Login query failed: {exc}", "error")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/system", methods=["GET", "POST"])
    def system():
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip()
            package_name = request.form.get("package_name", "").strip()
            sector = request.form.get("sector", "").strip()
            if not name:
                flash("Customer name is required.", "error")
            else:
                try:
                    with db() as con:
                        if vulnerable:
                            # Keeping this query vulnerable for the customer-form demo.
                            sql = ("INSERT INTO customers(name,email,package_name,sector,created_by) VALUES ('" + name + "','" + email + "','" + package_name + "','" + sector + "'," + str(user["id"]) + ")")
                            con.execute(sql)
                        else:
                            con.execute(
                                "INSERT INTO customers(name,email,package_name,sector,created_by) VALUES (?,?,?,?,?)",
                                (name, email, package_name, sector, user["id"]),
                            )
                    flash(f"New customer entered: {name if vulnerable else html.escape(name)}", "success")
                except sqlite3.Error as exc:
                    flash(f"Customer query failed: {exc}", "error")
        with db() as con:
            customers = con.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
        return render_template("system.html", customers=customers)

    @app.route("/change-password", methods=["GET", "POST"])
    def change_password():
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if request.method == "POST":
            old = request.form.get("old_password", "")
            new = request.form.get("new_password", "")
            errors = validate_password(new, cfg)
            if not matches_password(old, user["salt"], user["password_hmac"]):
                errors.append("Existing password is incorrect.")
            with db() as con:
                history = con.execute(
                    "SELECT salt,password_hmac FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                    (user["id"], int(cfg["password"]["history_count"])),
                ).fetchall()
            if any(matches_password(new, item["salt"], item["password_hmac"]) for item in history):
                errors.append("The new password matches one of the last three passwords.")
            if errors:
                for error in errors:
                    flash(error, "error")
            else:
                salt, digest = make_password(new)
                with db() as con:
                    con.execute("UPDATE users SET salt=?, password_hmac=? WHERE id=?", (salt, digest, user["id"]))
                    con.execute(
                        "INSERT INTO password_history(user_id,salt,password_hmac,created_at) VALUES (?,?,?,?)",
                        (user["id"], salt, digest, datetime.now(timezone.utc).isoformat()),
                    )
                flash("Password changed.", "success")
                return redirect(url_for("system"))
        return render_template("change_password.html")

    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        if request.method == "POST":
            email = request.form.get("email", "").strip()
            with db() as con:
                user = con.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
                if user:
                    token = secrets.token_urlsafe(24)
                    token_sha1 = hashlib.sha1(token.encode("utf-8")).hexdigest()
                    con.execute(
                        "INSERT INTO reset_tokens(user_id,token_sha1,created_at) VALUES (?,?,?)",
                        (user["id"], token_sha1, datetime.now(timezone.utc).isoformat()),
                    )
                    write_reset_email(email, token)
            flash("If the email exists, a random reset value was sent.", "success")
            return redirect(url_for("reset_password"))
        return render_template("forgot_password.html")

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        if request.method == "POST":
            token = request.form.get("token", "")
            new = request.form.get("new_password", "")
            token_sha1 = hashlib.sha1(token.encode("utf-8")).hexdigest()
            errors = validate_password(new, cfg)
            with db() as con:
                record = con.execute(
                    "SELECT * FROM reset_tokens WHERE token_sha1=? AND used=0 ORDER BY id DESC LIMIT 1",
                    (token_sha1,),
                ).fetchone()
                if not record:
                    errors.append("Reset value is invalid or already used.")
                if record:
                    history = con.execute(
                        "SELECT salt,password_hmac FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
                        (record["user_id"], int(cfg["password"]["history_count"])),
                    ).fetchall()
                    if any(matches_password(new, item["salt"], item["password_hmac"]) for item in history):
                        errors.append("The new password matches one of the last three passwords.")
                if errors:
                    for error in errors:
                        flash(error, "error")
                else:
                    salt, digest = make_password(new)
                    con.execute("UPDATE users SET salt=?,password_hmac=?,failed_attempts=0,locked=0 WHERE id=?", (salt, digest, record["user_id"]))
                    con.execute("UPDATE reset_tokens SET used=1 WHERE id=?", (record["id"],))
                    con.execute(
                        "INSERT INTO password_history(user_id,salt,password_hmac,created_at) VALUES (?,?,?,?)",
                        (record["user_id"], salt, digest, datetime.now(timezone.utc).isoformat()),
                    )
                    flash("Password reset completed.", "success")
                    return redirect(url_for("login"))
        return render_template("reset_password.html")

    return app
