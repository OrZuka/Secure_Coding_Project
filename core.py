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
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, session, url_for
from markupsafe import Markup


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


def password_reused(con, user_id: int, new_password: str, history_count: int) -> bool:
    """True if new_password matches any of the user's last `history_count` passwords.
    Each history row keeps its own salt, so the candidate is hashed per row."""
    rows = con.execute(
        "SELECT salt, password_hmac FROM password_history WHERE user_id=? ORDER BY id DESC LIMIT ?",
        (user_id, history_count),
    ).fetchall()
    return any(matches_password(new_password, row["salt"], row["password_hmac"]) for row in rows)


def set_password(con, user_id: int, new_password: str) -> None:
    """Hash the new password, replace the user's credential, and append it to their history."""
    salt, digest = make_password(new_password)
    con.execute("UPDATE users SET salt=?, password_hmac=? WHERE id=?", (salt, digest, user_id))
    con.execute(
        "INSERT INTO password_history(user_id,salt,password_hmac,created_at) VALUES (?,?,?,?)",
        (user_id, salt, digest, datetime.now(timezone.utc).isoformat()),
    )


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
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

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
                    username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                    email TEXT UNIQUE NOT NULL,
                    salt TEXT NOT NULL,
                    password_hmac TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked INTEGER NOT NULL DEFAULT 0,
                    locked_until TEXT
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
                    id_number TEXT,
                    phone TEXT,
                    area TEXT,
                    package TEXT,
                    created_by INTEGER,
                    FOREIGN KEY(created_by) REFERENCES users(id)
                );
                CREATE TABLE IF NOT EXISTS reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_hash TEXT NOT NULL,
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

    def authenticate(con, username, password):
        """Return (user_row, authenticated). The vulnerable build concatenates username AND
        password into the SQL (Slide 25) so a `' OR '1'='1' -- ` payload bypasses the check;
        the secure build parameterizes the lookup and verifies the password in Python."""
        if vulnerable:
            row = con.execute("SELECT * FROM users WHERE username = '" + username + "'").fetchone()
            digest = password_digest(password, bytes.fromhex(row["salt"] if row else "00"))
            auth_row = con.execute(
                "SELECT * FROM users WHERE username = '" + username
                + "' AND password_hmac = '" + digest + "'"
            ).fetchone()
            return (auth_row or row), (auth_row is not None)
        user = con.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return user, (bool(user) and matches_password(password, user["salt"], user["password_hmac"]))

    def send_reset_email(email: str, token: str) -> None:
        mail_cfg = cfg["mail"]
        subject = "Communication_LTD password reset code"
        body = f"Your Communication_LTD password reset code: {token}"
        if mail_cfg.get("mode") == "smtp":
            # Real delivery. Credentials come from the environment, never from config/source.
            import smtplib
            from email.message import EmailMessage

            smtp = mail_cfg.get("smtp", {})
            username = os.environ.get("COMMUNICATION_LTD_SMTP_USER")
            password = os.environ.get("COMMUNICATION_LTD_SMTP_PASS")
            message = EmailMessage()
            message["Subject"] = subject
            message["From"] = smtp.get("from_address") or username
            message["To"] = email
            message.set_content(body)
            with smtplib.SMTP(smtp.get("host", "localhost"), int(smtp.get("port", 587))) as server:
                if smtp.get("use_tls", True):
                    server.starttls()
                if username and password:
                    server.login(username, password)
                server.send_message(message)
        else:
            # File mode: simulate delivery to the version's outbox for offline development.
            outbox = version_dir / mail_cfg["outbox_file"]
            with outbox.open("a", encoding="utf-8") as handle:
                handle.write(f"To: {email}\n{subject}: {token}\n\n")

    def encode(value):
        # Secure build encodes special characters before display (the Jinja equivalent of
        # Server.HtmlEncode); the vulnerable build renders raw input, which is what allows Stored XSS.
        text = "" if value is None else str(value)
        return Markup(text) if vulnerable else Markup(html.escape(text))

    @app.context_processor
    def template_context():
        return {"current_user": current_user(), "version": version, "vulnerable": vulnerable, "encode": encode}

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            password_confirmation = request.form.get("password_confirmation", "")
            errors = validate_password(password, cfg)
            if not username or not email:
                errors.append("Username and email are required.")
            if password != password_confirmation:
                errors.append("Password confirmation does not match.")
            if errors:
                for error in errors:
                    flash(error, "error")
                return render_template("register.html", username=username, email=email)
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
                flash(f"User {username} was registered.", "success")
                return redirect(url_for("login"))
            except sqlite3.Error as exc:
                flash(f"Registration failed: {exc}" if vulnerable else "Registration could not be completed. Please try again with different details.", "error")
                return render_template("register.html", username=username, email=email)
        return render_template("register.html", username="", email="")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            try:
                with db() as con:
                    user, authenticated = authenticate(con, username, password)
                    max_attempts = int(cfg["login"]["max_attempts"])
                    lockout_minutes = int(cfg["login"].get("lockout_minutes", 30))
                    now = datetime.now(timezone.utc)

                    # Auto-release a lock whose window has elapsed, then re-read the user.
                    if user and user["locked"] and user["locked_until"]:
                        if now >= datetime.fromisoformat(user["locked_until"]):
                            con.execute(
                                "UPDATE users SET locked = 0, failed_attempts = 0, locked_until = NULL WHERE id = ?",
                                (user["id"],),
                            )
                            user = con.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

                    if not user:
                        # Vulnerable build leaks user existence on purpose (see B7 demo);
                        # secure build returns one generic message to prevent username enumeration.
                        flash("User does not exist." if vulnerable else "Incorrect username or password.", "error")
                    elif user["locked"]:
                        flash(f"Account is locked after {max_attempts} failed attempts. Try again in up to {lockout_minutes} minutes.", "error")
                    elif authenticated:
                        con.execute("UPDATE users SET failed_attempts = 0, locked = 0, locked_until = NULL WHERE id = ?", (user["id"],))
                        session.clear()
                        session["user_id"] = user["id"]
                        return redirect(url_for("system"))
                    else:
                        attempts = user["failed_attempts"] + 1
                        locked = int(attempts >= max_attempts)
                        locked_until = (now + timedelta(minutes=lockout_minutes)).isoformat() if locked else None
                        con.execute(
                            "UPDATE users SET failed_attempts = ?, locked = ?, locked_until = ? WHERE id = ?",
                            (attempts, locked, locked_until, user["id"]),
                        )
                        if vulnerable:
                            msg = "Incorrect password." if not locked else f"Account locked after {max_attempts} failed attempts."
                        else:
                            msg = "Incorrect username or password." if not locked else f"Account locked after {max_attempts} failed attempts. Try again in up to {lockout_minutes} minutes."
                        flash(msg, "error")
            except sqlite3.Error as exc:
                flash(f"Login query failed: {exc}" if vulnerable else "Login failed. Please try again.", "error")
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
            id_number = request.form.get("id_number", "").strip()
            phone = request.form.get("phone", "").strip()
            area = request.form.get("area", "").strip()
            package = request.form.get("package", "").strip()
            allowed_packages = {"basic", "premium", "unlimited"}
            if not name:
                flash("Customer name is required.", "error")
            elif package not in allowed_packages:
                flash("Please choose a valid package (basic, premium, or unlimited).", "error")
            else:
                try:
                    with db() as con:
                        if vulnerable:
                            # Keeping this query vulnerable for the customer-form demo.
                            sql = ("INSERT INTO customers(name,id_number,phone,area,package,created_by) VALUES ('" + name + "','" + id_number + "','" + phone + "','" + area + "','" + package + "'," + str(user["id"]) + ")")
                            con.execute(sql)
                        else:
                            con.execute(
                                "INSERT INTO customers(name,id_number,phone,area,package,created_by) VALUES (?,?,?,?,?,?)",
                                (name, id_number, phone, area, package, user["id"]),
                            )
                    flash(f"New customer entered: {name}", "success")
                except sqlite3.Error as exc:
                    flash(f"Customer query failed: {exc}" if vulnerable else "Could not save the customer. Please try again.", "error")
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
            history_count = int(cfg["password"]["history_count"])
            errors = validate_password(new, cfg)
            if not matches_password(old, user["salt"], user["password_hmac"]):
                errors.append("Existing password is incorrect.")
            with db() as con:
                if password_reused(con, user["id"], new, history_count):
                    errors.append(f"The new password matches one of the last {history_count} passwords.")
                if errors:
                    for error in errors:
                        flash(error, "error")
                else:
                    set_password(con, user["id"], new)
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
                    # Brief §A5: the emailed value is defined using SHA-1; we store only a hash of it.
                    reset_code = hashlib.sha1(secrets.token_bytes(32)).hexdigest()
                    code_hash = hashlib.sha256(reset_code.encode("utf-8")).hexdigest()
                    con.execute(
                        "INSERT INTO reset_tokens(user_id,token_hash,created_at) VALUES (?,?,?)",
                        (user["id"], code_hash, datetime.now(timezone.utc).isoformat()),
                    )
                    send_reset_email(email, reset_code)
            flash("If the email exists, a reset code has been sent to it.", "success")
            return redirect(url_for("reset_password"))
        return render_template("forgot_password.html")

    @app.route("/reset-password", methods=["GET", "POST"])
    def reset_password():
        if request.method == "POST":
            token = request.form.get("token", "")
            new = request.form.get("new_password", "")
            code_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
            history_count = int(cfg["password"]["history_count"])
            errors = validate_password(new, cfg)
            with db() as con:
                record = con.execute(
                    "SELECT * FROM reset_tokens WHERE token_hash=? AND used=0 ORDER BY id DESC LIMIT 1",
                    (code_hash,),
                ).fetchone()
                if not record:
                    errors.append("Reset code is invalid or already used.")
                elif password_reused(con, record["user_id"], new, history_count):
                    errors.append(f"The new password matches one of the last {history_count} passwords.")
                if errors:
                    for error in errors:
                        flash(error, "error")
                else:
                    set_password(con, record["user_id"], new)
                    con.execute("UPDATE users SET failed_attempts=0, locked=0, locked_until=NULL WHERE id=?", (record["user_id"],))
                    con.execute("UPDATE reset_tokens SET used=1 WHERE id=?", (record["id"],))
                    flash("Password reset completed.", "success")
                    return redirect(url_for("login"))
        return render_template("reset_password.html")

    return app
