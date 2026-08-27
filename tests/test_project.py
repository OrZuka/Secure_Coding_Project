import sys
import tempfile
import unittest
from pathlib import Path

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
                data={"username": "student", "email": "student@example.test", "password": "StrongPass1!"},
            )
            self.assertEqual(response.status_code, 302)
            response = client.post("/login", data={"username": "student", "password": "StrongPass1!"})
            self.assertEqual(response.status_code, 302)
            response = client.post(
                "/system",
                data={"name": "<script>alert('x')</script>", "email": "customer@example.test", "package_name": "Package A", "sector": "Education"},
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
                data={"username": "labuser", "email": "lab@example.test", "password": "StrongPass1!"},
            )
            client.post("/login", data={"username": "labuser", "password": "StrongPass1!"})
            payload = '<script>alert("stored")</script>'
            response = client.post(
                "/system",
                data={"name": payload, "email": "", "package_name": "", "sector": ""},
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
                data={"username": "lockeduser", "email": "locked@example.test", "password": "StrongPass1!"},
            )
            for _ in range(3):
                client.post("/login", data={"username": "lockeduser", "password": "WrongPass1!"})
            response = client.post(
                "/login",
                data={"username": "lockeduser", "password": "StrongPass1!"},
                follow_redirects=True,
            )
            self.assertIn(b"Account is locked", response.data)


if __name__ == "__main__":
    unittest.main()
