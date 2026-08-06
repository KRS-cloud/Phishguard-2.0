# PhishGuard AI & ML

PhishGuard is a defensive B.Tech CSE (AI & ML) project developed by
Pankaj Pawar. It demonstrates passive phishing-risk analysis with Flask,
explainable security rules, a small machine-learning model and optional
Google Gemini guidance.

The project is intended for cybersecurity awareness, classroom evaluation
and defensive learning. It is not a browser, antivirus product, threat-feed
service or guarantee that submitted content is safe.

## Features

- Account registration, login, logout and signed password-reset links
- URL structure analysis without visiting the destination
- Email-text analysis for social-engineering indicators
- QR decoding without automatically opening the destination
- Browser-only password generation using the Web Crypto API
- Personal scan history, PDF reports and CSV export
- Optional Google Gemini security assistant with a local fallback
- Administrator usage statistics without exposing scan inputs in the feed
- CSRF protection, request rate limits and production security headers

The public deployment does **not** include a password-strength checker.
Users should never submit passwords, OTPs, private keys, financial details
or confidential content to an analyzer or AI assistant.

## How analysis works

1. The application validates user-controlled input.
2. Explainable rules extract structural warning indicators.
3. URL rules may be blended with a local Random Forest prediction.
4. The interface presents a risk estimate, reasons and safety guidance.
5. A minimized summary is stored in the signed-in user's history.

URL and QR destinations are not fetched or opened. Email analysis operates
only on text the user deliberately pastes; it does not access a mailbox.

## Privacy design

- URL history retains only the origin, such as `https://example.com`.
  Credentials, paths, query strings and fragments are discarded.
- Email sender, subject and body are not retained in scan history.
- QR images are not saved. Full decoded text is not retained in history.
- Passwords are stored only as Werkzeug password hashes.
- The password generator runs entirely in the browser.
- AI assistant questions may be sent to Google Gemini. PhishGuard does not
  retain the assistant conversation in its session cookie.
- Neon hosts production account/history data and Brevo sends transactional
  password-recovery email.

See the in-app About, Privacy and Security pages for user-facing notices.

## Technology

- Python 3.13 and Flask
- Flask-SQLAlchemy with SQLite locally and PostgreSQL/Neon in production
- Flask-Login, Flask-WTF CSRF and Flask-Limiter
- scikit-learn, pandas and joblib
- OpenCV and Pillow for QR processing
- Google GenAI SDK for the optional assistant
- Brevo transactional email API
- HTML, CSS and JavaScript

## Project structure

```text
app/
  ml/             Feature extraction
  models/         SQLAlchemy models
  routes/         Flask blueprints
  services/       Analysis, AI and email services
  static/         CSS and browser JavaScript
  templates/      Jinja templates
tests/            unittest regression suite
trained_models/   Serialized URL model
training/         Reproducible training script and small dataset
config.py         Environment-based application configuration
run.py            Local and Gunicorn application entry point
```

## Run locally

### 1. Create and activate a virtual environment

PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 3. Configure the environment

Copy `.env.example` to `.env`, then replace every placeholder with your own
value. Never commit `.env`.

Generate a secret key without printing an existing secret:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

For local development, SQLite is used when `DATABASE_URL` is omitted.

### 4. Start the application

```powershell
python run.py
```

Open `http://127.0.0.1:5000` on the same computer.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Random secret of at least 32 characters; required |
| `APP_ENV` | `development` locally or `production` when deployed |
| `DATABASE_URL` | PostgreSQL/Neon pooled URL; required in production |
| `APP_BASE_URL` | Public HTTPS origin used in reset links |
| `GEMINI_API_KEY` | Optional Google Gemini API credential |
| `GEMINI_MODEL` | Gemini model name |
| `BREVO_API_KEY` | Brevo transactional email API credential |
| `BREVO_SENDER_EMAIL` | Verified Brevo sender address |
| `BREVO_SENDER_NAME` | Sender display name |
| `PASSWORD_RESET_MAX_AGE` | Reset-token lifetime in seconds |
| `RATELIMIT_STORAGE_URI` | Flask-Limiter storage URI |
| `COOKIE_SECURE` | Set `true` for HTTPS outside detected production |
| `TRUST_PROXY` | Set `true` only behind a trusted single reverse proxy |

All real credentials belong only in `.env` or the hosting provider's secret
environment settings. `.env.example` contains placeholders only.

## Tests

Run the full suite from the project root:

```powershell
python -m unittest discover -v
```

Also run syntax validation before deployment:

```powershell
python -m compileall app tests config.py run.py
```

On Windows, the repository also includes one combined safety check:

```powershell
.\scripts\predeploy_check.ps1
```

## Production deployment

Use a new service only after reviewing the public pages, dependency lock and
environment values. A typical Gunicorn start command is:

```text
gunicorn run:app --bind 0.0.0.0:$PORT --workers 1 --threads 2 --timeout 120
```

Required production settings include:

```env
APP_ENV=production
SECRET_KEY=<new-random-secret>
DATABASE_URL=<new-Neon-pooled-connection-url>
APP_BASE_URL=https://your-service.example
COOKIE_SECURE=true
TRUST_PROXY=true
```

Add the Brevo and Gemini settings only through the host's secret environment
configuration. Do not paste credentials into source files, commits, logs,
screenshots or support messages.

## Model limitations

The included Random Forest is a proof of concept trained on only 79 labelled
examples (40 low-risk and 39 synthetic phishing-style URLs). Its measured
test accuracy is not evidence of real-world protection because the dataset is
small and synthetic. Results may contain false positives and false negatives.
Always verify important decisions using authoritative sources and established
security products.

## Responsible use

Use PhishGuard only with content you are authorized to analyze. Do not use the
project for impersonation, credential collection, unauthorized testing or
misleading users. The implementation and public interface are intentionally
transparent about who operates it, what it processes and its limitations.
