$ErrorActionPreference = "Stop"

if (-not (Test-Path ".git")) {
    throw "Run this script from the Git repository root."
}

Write-Host "1/6 Checking tracked file safety..."

$blockedFiles = git ls-files |
    Where-Object {
        $_ -match '(^|/)\.env$|(^|/)(venv/|__pycache__/|instance/)' -or
        $_ -match '\.py[co]$|\.db$|\.sqlite3?$'
    }

if ($blockedFiles) {
    $blockedFiles | ForEach-Object { Write-Host "Blocked: $_" }
    throw "Forbidden local files are tracked by Git."
}

if (-not (git check-ignore ".env" 2>$null)) {
    throw ".env is not ignored by Git."
}

Write-Host "2/6 Scanning tracked text for common secret formats..."

$secretPattern = (
    'AQ\.[A-Za-z0-9_-]{20,}|' +
    'AIza[A-Za-z0-9_-]{20,}|' +
    'xkeysib-[A-Za-z0-9_-]{20,}|' +
    'npg_[A-Za-z0-9]{8,}|' +
    'postgres(ql)?://[^[:space:]]+:[^[:space:]@]+@|' +
    'SECRET_KEY=[a-fA-F0-9]{32,}'
)

$secretFiles = git grep -l -I -E $secretPattern -- . 2>$null

if ($secretFiles) {
    $secretFiles | ForEach-Object { Write-Host "Possible secret: $_" }
    throw "Possible secrets were found. Do not commit or deploy."
}

Write-Host "3/6 Checking requirements encoding..."

python -c "from pathlib import Path; p=Path('requirements.txt'); assert p.read_bytes().count(b'\0') == 0; p.read_text(encoding='utf-8'); print('requirements.txt: UTF-8 OK')"

if ($LASTEXITCODE -ne 0) {
    throw "requirements.txt validation failed."
}

Write-Host "4/6 Checking Python syntax..."
python -m compileall -q app tests config.py run.py

if ($LASTEXITCODE -ne 0) {
    throw "Python syntax validation failed."
}

Write-Host "5/6 Verifying the ML model checksum..."

$expectedHash = (
    Get-Content "trained_models/url_phishing_model.sha256" -Raw
).Trim().ToLower()

$actualHash = (
    Get-FileHash "trained_models/url_phishing_model.joblib" -Algorithm SHA256
).Hash.ToLower()

if ($expectedHash -ne $actualHash) {
    throw "ML model checksum mismatch."
}

Write-Host "6/6 Running regression tests..."
python -m unittest discover -v

if ($LASTEXITCODE -ne 0) {
    throw "Regression tests failed."
}

git diff --check

if ($LASTEXITCODE -ne 0) {
    throw "Git found whitespace errors."
}

git diff --cached --check

if ($LASTEXITCODE -ne 0) {
    throw "Git found whitespace errors in staged changes."
}

Write-Host "PREDEPLOY CHECK PASSED" -ForegroundColor Green
