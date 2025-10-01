# PhishSentry — A Guard That Catches Phishing

PhishSentry is a simple, local Python IMAP scanner that inspects unread Gmail messages for phishing indicators and suspicious attachments.  
It flags and moves suspicious emails to Gmail Spam, logs results locally, and can optionally check attachment hashes via VirusTotal.

> **Important goal:** keep everything local — the script is intended to help you convert email signals into local logs and actions. Do **not** push secrets or plaintext credentials to GitHub.

---

## Quick summary (one-liner)
Scans unread Gmail messages via IMAP, detects phishing/malware signals, logs findings to `email_threat_scan.log`, and moves flagged messages to Gmail Spam. Optional VirusTotal hash checks available.

---

## Required dependencies
Install these before running (listed here so no `requirements.txt` is required):

```bash
pip install tldextract pyspellchecker keyring
````

Optional (only if you enable VirusTotal lookups):

```bash
pip install requests
```

* `tldextract` — domain parsing and lookalike detection
* `pyspellchecker` — simple spelling error detection
* `keyring` — secure local storage for your Gmail app password (recommended)
* `requests` — optional, for VirusTotal API calls

---

## IMAP & Credentials — Must read

* The script uses **IMAP** to read Gmail. IMAP must be enabled in your Google account settings.
* **Do not** use your normal Gmail password. IMAP access should use an **App Password** (recommended) or OAuth2 token.
* A **hashed** password (e.g., a stored hash) **cannot** be used to authenticate with Gmail. Hashes are for verification only; IMAP needs the actual token string.

### Recommended credential storage (safe)

1. **Preferred:** store the app password in your OS keyring (secure) and let the script read it.

   ```bash
   pip install keyring
   python -c "import keyring; keyring.set_password('PhishSentry','GMAIL_APP_PASSWORD','<PASTE_TOKEN>')"
   ```

   The script will call:

   ```py
   import keyring
   pw = keyring.get_password('PhishSentry','GMAIL_APP_PASSWORD')
   ```
2. **Fallback:** export as environment variables (less secure but simple):

   ```bash
   export GMAIL_ADDRESS="youremail@gmail.com"
   export GMAIL_APP_PASSWORD="your_app_password_here"
   ```

The script will attempt `keyring` first, then fall back to environment variables. If neither is set it will exit with a clear instruction.

---

## VirusTotal & other API notes (optional)

* If you want extra malware intelligence, the script can compute attachment SHA256 hashes and query VirusTotal for known malicious indicators.
* To enable this feature you need an API key from VirusTotal (or similar service). Store it in an environment variable:

  ```bash
  export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
  ```
* The script will only send hashes (not upload files) when checking VT; you can change behavior in the code if you want uploads (not recommended without consent).

---

## How to run (step-by-step)

1. Clone or place the script locally:

   ```bash
   mkdir -p ~/PhishSentry
   # put phishing_detector.py into ~/PhishSentry
   cd ~/PhishSentry
   ```

2. Install dependencies:

   ```bash
   pip install tldextract pyspellchecker keyring
   # optional:
   pip install requests
   ```

3. Enable Gmail IMAP and create an App Password:

   * Google Account → Security → App passwords → create `Mail / Other` app password
   * Copy the token (the 16-character string)

4. Store the token (choose one):

   * Keyring (recommended):

     ```bash
     python -c "import keyring; keyring.set_password('PhishSentry','GMAIL_APP_PASSWORD','<PASTE_TOKEN>')"
     ```
   * Or environment variables:

     ```bash
     export GMAIL_ADDRESS="youremail@gmail.com"
     export GMAIL_APP_PASSWORD="your_app_password_here"
     # optional VT key:
     export VIRUSTOTAL_API_KEY="your_vt_key_here"
     ```

5. Run the scanner:

   ```bash
   python3 phishing_detector.py
   ```

6. What happens:

   * Unread inbox messages are scanned.
   * Suspicious messages are logged to `email_threat_scan.log`.
   * Flagged messages are copied to Gmail Spam and deleted from Inbox (IMAP actions).
   * Attachments that match suspicious patterns are reported; if VT key is present, attachment hashes may be checked.

---

## Files & privacy

* `email_threat_scan.log` — local log file (contains scan events). This file is included in `.gitignore` by default to avoid accidental upload.
* Do **not** commit `GMAIL_APP_PASSWORD` or any secrets to the repo.

Suggested `.gitignore`:

```
email_threat_scan.log
.env
__pycache__/
*.pyc
```

---

## Tuning & tips

* Adjust the spelling-error threshold and suspicious-link heuristics in the script if you get too many false positives.
* Add a whitelist of safe domains for your use case (`safe_domains` set).
* If you use a corporate mailbox or OAuth2, integrate an OAuth token workflow instead of app passwords.

---

## Legal & ethical notice

This tool is for **defensive, personal use only** — scanning your own mailbox for threats. Do not use it to access accounts you do not own or have explicit permission to monitor.

---

## Example quick troubleshooting

* `imaplib.IMAP4.error: LOGIN failed` → check app password and that IMAP is enabled.
* Script exits with "no credentials" → set keyring value or export env vars as shown above.
* Too many false positives → increase spelling-error threshold or expand `safe_domains`.

---

## License

MIT License — see `LICENSE` in this repo.

```

---
