# Communication_LTD cyber final project

This is my Communication_LTD web project. There are two versions so the vulnerable and fixed code can be tested separately:

- `secure_version`: protected SQL statements use parameters and displayed user data is HTML-encoded by Jinja auto-escaping.
- `vulnerable_version`: Register, Login, and Customer use unsafe SQL strings, and the customer list renders stored data without encoding for the SQLi and Stored-XSS demos.

The vulnerable version is for an isolated classroom lab only. Never expose it to a network or real data.

## Setup

Use Python 3.11 or newer from this folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run the secure version:

```powershell
python secure_version\app.py
```

Run the vulnerable version on its separate port:

```powershell
python vulnerable_version\app.py
```

Open `http://127.0.0.1:5000` for secure or `http://127.0.0.1:5001` for vulnerable.

Each version creates its own SQLite relational database. Password policy and login attempt limits are managed in `config.json`. Reset messages are written to the version's `mail_outbox.txt`, simulating delivery to the user's registered email without requiring external mail credentials.

## Main flows

1. Register with username, email, and a policy-compliant password.
2. Login; after three failed attempts the account is locked.
3. Change password by supplying the existing password; the last three passwords cannot be reused.
4. Add a customer and display the entered customer's name.
5. Forgot password generates a reset code, stores its SHA-1 digest, and sends the code to the configured file outbox. Use the emailed code on the reset-password screen.

## Classroom demonstrations

Use only fake data in the vulnerable version.

- Stored XSS: add a customer name such as `<script>alert("Stored XSS")</script>`; the vulnerable customer list executes it, while the secure list displays it as text.
- SQL injection: compare the SQL strings in `core.py` for Register, Login, and Add Customer with the parameterized queries in the secure version.
- Encoding: compare the vulnerable `|safe` customer rendering with normal Jinja rendering in the secure template.

The unsafe queries have short comments next to them so they are easy to find during the demo.
