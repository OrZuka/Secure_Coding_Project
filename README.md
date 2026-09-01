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
    "mode": "smtp",
    "outbox_file": "mail_outbox.txt",
    "smtp": { "host": "smtp-relay.brevo.com", "port": 587, "use_tls": true, "from_address": "REPLACE_WITH_VERIFIED_BREVO_SENDER" }
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

Two modes, switched with `mail.mode`:

- **`"file"`** (offline dev): reset codes are appended to the version's `mail_outbox.txt` — no network, no account.
- **`"smtp"`** (real delivery): the code is emailed via the configured SMTP relay.

The repo is configured for real delivery through **Brevo** (a free transactional-email provider — no
personal mailbox, no 2FA/app-password setup). Everything except the two credentials lives in
`config.json`; the credentials come from **environment variables and are never committed** (this is a
public repo — a committed SMTP key gets scanned, revoked, and abused).

**One-time provider setup (do once per sender):**

1. Sign up free at [brevo.com](https://www.brevo.com).
2. **Verify a sender address** (Senders & Domains → add a sender → click the confirmation email). This
   verified address is what you put in `smtp.from_address` in `config.json`. Sending will be *rejected*
   if `from_address` is not a verified sender.
3. **SMTP & API → SMTP → generate an SMTP key.** The panel shows your **login** (e.g.
   `xxxxxx@smtp-brevo.com`) and lets you copy the **key**.

**Credentials via `.env` (recommended).** Copy the template and fill in your values — the app
auto-loads `.env` on startup (via `python-dotenv`), so you set the key once instead of exporting it
every run:

```bash
cp .env.example .env
# then edit .env and paste your Brevo SMTP key into COMMUNICATION_LTD_SMTP_PASS
python secure_version/app.py
```

`.env` is gitignored (`.env.example` is the committed template) — **never commit `.env`**. The SMTP key
is the only secret; share it with a teammate out-of-band (a DM or password-manager note), or each
teammate makes their own free Brevo account and uses their own key. Prefer not to use a file? Export
the same three variables in your shell instead. If credentials are missing, Forgot Password logs the
error and shows the generic "if the email exists…" message instead of crashing — so the app still runs,
it just doesn't send.

Any other SMTP provider works too: swap `smtp.host`/`smtp.port` and set the same two env vars. For a
fully offline demo, set `mail.mode` back to `"file"` and read the code from `mail_outbox.txt`.

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
