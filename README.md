# Communication_LTD — Cyber Final Project

A web information system for the fictional ISP **Communication_LTD**, built to demonstrate secure
coding principles alongside the two attacks from the course: SQL Injection and Stored XSS.

The project ships in **two versions that share one codebase** (`core.py`). A single `vulnerable`
flag flips the handful of places that differ, so ~90% of the code is identical between them:

- **`secure_version`** — parameterized SQL everywhere, and user data is HTML-encoded before display.
- **`vulnerable_version`** — Register, Login and Add-Customer build SQL by string concatenation, and
  the customer list renders stored input without encoding, for the required SQLi and Stored-XSS demos.

> The vulnerable version is for an isolated classroom lab only. Never expose it to a network or real data.

## Setup

Python 3.11+ from the project folder:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Run each version (they use separate ports and separate databases):

```bash
python secure_version/app.py       # http://127.0.0.1:5050
python vulnerable_version/app.py    # http://127.0.0.1:5001
```

Use `127.0.0.1`, not `localhost` — on macOS, `localhost:5000` is intercepted by AirPlay, which is why
the secure app listens on 5050.

Each version creates its own SQLite relational database on first run. Deleting a `*.db` file simply
recreates the schema on the next launch (they are gitignored, as is `mail_outbox.txt`).

## Configuration — `config.json`

All security policy is admin-tunable here. Changes take effect on the next app start.

```json
{
  "password": {
    "min_length": 10,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digit": true,
    "require_special": true,
    "history_count": 3,
    "dictionary_file": "password_dictionary.txt"
  },
  "login": {
    "max_attempts": 3,
    "lockout_minutes": 30
  },
  "mail": {
    "mode": "file",
    "outbox_file": "mail_outbox.txt",
    "smtp": { "host": "smtp.gmail.com", "port": 587, "use_tls": true, "from_address": "" }
  }
}
```

| Key | Meaning |
| --- | --- |
| `min_length` | Minimum password length. |
| `require_uppercase / lowercase / digit / special` | Character-class requirements for a complex password. |
| `history_count` | How many previous passwords cannot be reused. Raising it looks further back immediately (full history is retained). |
| `dictionary_file` | External banned-password list; edit the file to grow it, no code change needed. |
| `max_attempts` | Failed logins before the account locks. |
| `lockout_minutes` | How long an account stays locked; the next attempt after the window auto-releases it. |
| `mail.mode` | `"file"` writes reset codes to the outbox (offline dev); `"smtp"` sends real email. |

### Email delivery

In `"file"` mode, reset codes are appended to the version's `mail_outbox.txt`. To send real email, set
`mail.mode` to `"smtp"`, fill in the `smtp` block, and provide credentials via **environment variables**
(never commit them):

```bash
export COMMUNICATION_LTD_SMTP_USER="you@example.com"
export COMMUNICATION_LTD_SMTP_PASS="an-app-password"
```

Set `COMMUNICATION_LTD_SECRET` too, to keep sessions stable across restarts.

## Main flows

1. **Register** — username, email, and a policy-compliant password. Passwords are stored as a salted
   HMAC (unique 32-byte salt per user); the plaintext is never stored.
2. **Login** — after `max_attempts` failures the account locks for `lockout_minutes`, then auto-unlocks.
   The secure build returns one generic failure message (no username enumeration).
3. **Change password** — requires the current password; the new one must pass the full policy and must
   not match the last `history_count` passwords.
4. **System (customers)** — add a customer (name, ID number, phone, area, package) and see the list.
   `package` is a dropdown validated server-side against `basic / premium / unlimited`.
5. **Forgot password** — generates a reset code **defined using SHA-1**, stores only a hash of it, and
   sends the code to the registered email. Enter the code on the reset screen to set a new password.

## Classroom demonstrations (vulnerable version only, fake data only)

- **Stored XSS** — add a customer whose name is `<script>alert(document.cookie)</script>`. The
  vulnerable list renders it raw and it executes for anyone who opens the page; the secure list shows it
  as text. Defense: the secure build calls `html.escape()` (via the `encode()` helper in `core.py`),
  the encoding equivalent of `Server.HtmlEncode`.
- **SQL Injection** — the vulnerable Register, Login and Add-Customer queries concatenate input.
  - Login auth-bypass: put `' OR '1'='1' -- ` in the **username** field.
    Note: SQLite's comment token is `--` (with a trailing space), **not** MySQL's `#`. Typing `#` here
    raises `unrecognized token: "#"`, which also demonstrates the reflected-error-message issue.
  - The secure version uses parameterized queries and blocks all of the above.

## Tests

```bash
python -m unittest discover -s tests
```

Covers password hashing and policy, secure register/login/customer, the account-lockout flow, the
Stored-XSS lab, and the login SQL-injection bypass (present in vulnerable, blocked in secure).
