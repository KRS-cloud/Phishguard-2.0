# PhishGuard Security Policy

PhishGuard is a defensive student cybersecurity project. The current `main`
branch is the only supported version.

## Safe-use boundary

- PhishGuard never asks for a password from Google, a bank, a college, a
  workplace or another third-party service.
- The public password utility generates values entirely in the browser and
  does not send them to the server.
- URL and decoded QR destinations are analyzed passively and are not opened.
- Users must not submit passwords, OTPs, private keys, financial details,
  confidential communications or content they are not authorized to analyze.
- Risk results are educational estimates, not guarantees of safety.

## Reporting a vulnerability

Use the repository's GitHub Issues page to make initial contact with the
project owner:

<https://github.com/KRS-cloud/Phishguard-2.0/issues>

Do not include live credentials, reset tokens, private user data or a working
exploit in a public issue. Describe the affected component and request a
private channel for sensitive technical details.

## Known limitations

The included URL model is a proof of concept trained on a small synthetic
dataset. It can produce false positives and false negatives. The project is
not a replacement for professional security controls or threat intelligence.
