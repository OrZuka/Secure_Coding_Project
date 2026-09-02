import smtplib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import create_app, load_config, make_password, matches_password, validate_password


class ProjectTests(unittest.TestCase):
    def test_hmac_and_policy(self):
        salt, digest = make_password("StrongPass1!")
        self.assertTrue(matches_password("StrongPass1!", salt, digest))
        self.assertFalse(matches_password("WrongPass1!", salt, digest))
        self.assertEqual(validate_password("StrongPass1!", load_config()), [])
        self.assertTrue(validate_password("short", load_config()))

    def test_secure_register_login_and_customer(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app("secure", Path(folder) / "test.db")
            app.config.update(TESTING=True, SECRET_KEY="test")
            client = app.test_client()
            response = client.post(
                "/register",
                data={"username": "student", "email": "student@example.test", "password": "StrongPass1!", "password_confirmation": "StrongPass1!"},
            )
            self.assertEqual(response.status_code, 302)
            response = client.post("/login", data={"username": "student", "password": "StrongPass1!"})
            self.assertEqual(response.status_code, 302)
            response = client.get("/system")
            self.assertNotIn(b">Register<", response.data)
            self.assertNotIn(b">Forgot password<", response.data)
            self.assertIn(b">Change password<", response.data)
            self.assertIn(b">Logout<", response.data)
            response = client.post(
                "/system",
                data={"name": "<script>alert('x')</script>", "id_number": "312345678", "phone": "050-1112222", "area": "North", "package": "basic"},
                follow_redirects=True,
            )
            self.assertIn(b"&lt;script&gt;", response.data)
            self.assertNotIn(b"<script>alert('x')</script>", response.data)

    def test_vulnerable_version_exposes_stored_xss_lab(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app("vulnerable", Path(folder) / "test.db")
            app.config.update(TESTING=True, SECRET_KEY="test")
            client = app.test_client()
            client.post(
                "/register",
                data={"username": "labuser", "email": "lab@example.test", "password": "StrongPass1!", "password_confirmation": "StrongPass1!"},
            )
            client.post("/login", data={"username": "labuser", "password": "StrongPass1!"})
            payload = '<script>alert("stored")</script>'
            response = client.post(
                "/system",
                data={"name": payload, "id_number": "", "phone": "", "area": "", "package": "basic"},
                follow_redirects=True,
            )
            self.assertIn(payload.encode(), response.data)

    def test_three_failed_logins_lock_account(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app("secure", Path(folder) / "test.db")
            app.config.update(TESTING=True, SECRET_KEY="test")
            client = app.test_client()
            client.post(
                "/register",
                data={"username": "lockeduser", "email": "locked@example.test", "password": "StrongPass1!", "password_confirmation": "StrongPass1!"},
            )
            for _ in range(3):
                client.post("/login", data={"username": "lockeduser", "password": "WrongPass1!"})
            response = client.post(
                "/login",
                data={"username": "lockeduser", "password": "StrongPass1!"},
                follow_redirects=True,
            )
            self.assertIn(b"Account is locked", response.data)

    def test_register_keeps_non_password_fields_and_checks_confirmation(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app("secure", Path(folder) / "test.db")
            app.config.update(TESTING=True, SECRET_KEY="test")
            client = app.test_client()
            response = client.post(
                "/register",
                data={
                    "username": "keep_me",
                    "email": "keep@example.test",
                    "password": "StrongPass1!",
                    "password_confirmation": "DifferentPass1!",
                },
                follow_redirects=True,
            )
            self.assertIn(b"Password confirmation does not match", response.data)
            self.assertIn(b'value="keep_me"', response.data)
            self.assertIn(b'value="keep@example.test"', response.data)


    def test_vulnerable_login_sqli_bypass(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app("vulnerable", Path(folder) / "test.db")
            app.config.update(TESTING=True, SECRET_KEY="test")
            client = app.test_client()
            client.post(
                "/register",
                data={"username": "cyber", "email": "c@example.test", "password": "StrongPass1!", "password_confirmation": "StrongPass1!"},
            )
            client.get("/logout")
            # SQLite comment token is --, not MySQL's #
            response = client.post(
                "/login",
                data={"username": "' OR '1'='1' -- ", "password": "anything"},
                follow_redirects=True,
            )
            self.assertIn(b"Customer System", response.data)  # bypass succeeds in vulnerable build

    def test_secure_login_resists_sqli_bypass(self):
        with tempfile.TemporaryDirectory() as folder:
            app = create_app("secure", Path(folder) / "test.db")
            app.config.update(TESTING=True, SECRET_KEY="test")
            client = app.test_client()
            client.post(
                "/register",
                data={"username": "cyber", "email": "c@example.test", "password": "StrongPass1!", "password_confirmation": "StrongPass1!"},
            )
            client.get("/logout")
            response = client.post(
                "/login",
                data={"username": "' OR '1'='1' -- ", "password": "anything"},
                follow_redirects=True,
            )
            self.assertNotIn(b"Customer System", response.data)  # parameterized query blocks it


    def test_migration_upgrades_old_schema_and_preserves_data(self):
        with tempfile.TemporaryDirectory() as folder:
            db_path = Path(folder) / "legacy.db"
            salt, digest = make_password("StrongPass1!")
            legacy = sqlite3.connect(db_path)
            legacy.executescript(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    salt TEXT NOT NULL,
                    password_hmac TEXT NOT NULL,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE customers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT,
                    package_name TEXT,
                    sector TEXT,
                    created_by INTEGER
                );
                CREATE TABLE reset_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token_sha1 TEXT NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                """
            )
            legacy.execute(
                "INSERT INTO users(username,email,salt,password_hmac) VALUES (?,?,?,?)",
                ("legacy", "legacy@example.test", salt, digest),
            )
            legacy.execute(
                "INSERT INTO customers(name,email,package_name,sector,created_by) VALUES (?,?,?,?,?)",
                ("Old Customer", "old@example.test", "premium", "South", 1),
            )
            legacy.execute(
                "INSERT INTO reset_tokens(user_id,token_sha1,created_at) VALUES (?,?,?)",
                (1, "deadbeef", "2024-01-01T00:00:00+00:00"),
            )
            legacy.commit()
            legacy.close()

            # create_app runs migrate_db against the existing database.
            app = create_app("secure", db_path)
            app.config.update(TESTING=True, SECRET_KEY="test")

            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            user_cols = {r["name"] for r in con.execute("PRAGMA table_info(users)")}
            customer_cols = {r["name"] for r in con.execute("PRAGMA table_info(customers)")}
            reset_cols = {r["name"] for r in con.execute("PRAGMA table_info(reset_tokens)")}
            self.assertIn("locked_until", user_cols)
            self.assertIn("area", customer_cols)
            self.assertIn("package", customer_cols)
            self.assertNotIn("email", customer_cols)
            self.assertIn("token_hash", reset_cols)
            customer = con.execute("SELECT * FROM customers WHERE id = 1").fetchone()
            self.assertEqual(customer["area"], "South")
            self.assertEqual(customer["package"], "premium")
            con.close()

            # The preserved user can still log in after migration.
            client = app.test_client()
            response = client.post("/login", data={"username": "legacy", "password": "StrongPass1!"})
            self.assertEqual(response.status_code, 302)

    def _smtp_app(self, folder):
        smtp_cfg = load_config()
        smtp_cfg["mail"] = {
            "mode": "smtp",
            "outbox_file": "mail_outbox.txt",
            "smtp": {"host": "smtp.example.test", "port": 587, "use_tls": True, "from_address": "noreply@example.test"},
        }
        with mock.patch("core.load_config", return_value=smtp_cfg):
            app = create_app("secure", Path(folder) / "test.db")
        app.config.update(TESTING=True, SECRET_KEY="test")
        client = app.test_client()
        client.post(
            "/register",
            data={"username": "mailer", "email": "mailer@example.test", "password": "StrongPass1!", "password_confirmation": "StrongPass1!"},
        )
        return client

    def test_forgot_password_smtp_failure_does_not_500(self):
        with tempfile.TemporaryDirectory() as folder:
            client = self._smtp_app(folder)
            with mock.patch("smtplib.SMTP", side_effect=smtplib.SMTPException("boom")):
                response = client.post("/forgot-password", data={"email": "mailer@example.test"})
            # Delivery failed but the request is handled gracefully, not a 500.
            self.assertEqual(response.status_code, 302)

    def test_forgot_password_smtp_success_sends_message(self):
        with tempfile.TemporaryDirectory() as folder:
            client = self._smtp_app(folder)
            server = mock.MagicMock()
            with mock.patch("smtplib.SMTP") as smtp_ctor:
                smtp_ctor.return_value.__enter__.return_value = server
                response = client.post("/forgot-password", data={"email": "mailer@example.test"})
            self.assertEqual(response.status_code, 302)
            server.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
