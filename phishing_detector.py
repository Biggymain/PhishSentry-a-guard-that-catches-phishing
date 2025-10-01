#!/usr/bin/env python3
import imaplib
import email
import re
import logging
import os
import hashlib
from email.header import decode_header
import tldextract
from spellchecker import SpellChecker

# ===== CONFIG =====
GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")  # safer than hardcoding
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
VIRUSTOTAL_API_KEY = None  # Optional: set to enable VT scanning

# ===== LOGGING =====
logging.basicConfig(filename="email_threat_scan.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# ===== SPELLCHECKER =====
spell = SpellChecker()

# ===== HELPER: Detect suspicious links =====
def is_suspicious_link(url):
    try:
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}"
        safe_domains = {"google.com", "microsoft.com", "paypal.com", "amazon.com"}  # whitelist

        # Not in whitelist → suspicious
        if domain not in safe_domains:
            # Lookalike detection: numbers in domain or extra hyphens
            if re.search(r"[0-9]", ext.domain) or "-" in ext.domain:
                return True
            # Multiple subdomains before main domain
            if ext.subdomain and len(ext.subdomain.split(".")) > 1:
                return True
        return False
    except Exception:
        return False

# ===== PHISHING CHECKS =====
def is_phishing(text):
    reasons = []

    # Urgency + link combo
    if re.search(r"(urgent|suspend|immediately|verify now)", text, re.IGNORECASE) and "http" in text:
        reasons.append("Urgency + link — possible phishing")

    # Suspicious links
    urls = re.findall(r"http[s]?://[^\s]+", text)
    for url in urls:
        if is_suspicious_link(url):
            reasons.append(f"Suspicious link: {url}")

    # Spelling errors threshold
    words = re.findall(r"[A-Za-z]+", text)
    misspelled = spell.unknown(words)
    if len(misspelled) >= 5:  # adjust threshold for precision
        reasons.append("Multiple spelling errors — suspicious")

    # Suspicious domains in URL text
    for url in urls:
        if re.search(r"(login|secure|account|verify)[-\.]", url, re.IGNORECASE):
            reasons.append(f"Suspicious domain pattern in: {url}")

    return reasons

# ===== MALWARE CHECKS =====
def is_malware_attachment(part):
    filename = part.get_filename()
    if not filename:
        return None

    filename = decode_header(filename)[0][0]
    if isinstance(filename, bytes):
        filename = filename.decode(errors="ignore")

    ext = os.path.splitext(filename)[1].lower()
    malware_exts = [".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar", ".ps1", ".msi", ".dll"]

    reasons = []
    if ext in malware_exts:
        reasons.append(f"Suspicious file extension: {ext}")

    # Detect macro-enabled Office files
    if ext in [".doc", ".xls", ".docm", ".xlsm", ".pptm"]:
        file_data = part.get_payload(decode=True)
        if b"vbaProject" in file_data:
            reasons.append("Office file contains macros — possible malware")

    if re.search(r"(password|invoice|urgent)", filename, re.IGNORECASE):
        reasons.append("Suspicious attachment name")

    # Optional VirusTotal check (only hash, no upload here)
    if VIRUSTOTAL_API_KEY:
        file_data = part.get_payload(decode=True)
        file_hash = hashlib.sha256(file_data).hexdigest()
        # Here you'd send the hash to VirusTotal

    return reasons if reasons else None

# ===== SCANNER =====
def scan_inbox():
    try:
        logging.info(f"Connecting to IMAP for {GMAIL_ADDRESS}")
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)

        # Only scan unread emails for performance
        mail.select("inbox")
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        for num in email_ids:
            status, data = mail.fetch(num, "(RFC822)")
            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)

            # Decode subject
            subject, encoding = decode_header(msg["Subject"])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or "utf-8", errors="ignore")

            # Body text
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_payload(decode=True).decode(errors="ignore")
            else:
                body = msg.get_payload(decode=True).decode(errors="ignore")

            # Run phishing check
            phishing_reasons = is_phishing(subject + "\n" + body)

            # Run malware check on attachments
            malware_reasons = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_disposition() == "attachment":
                        result = is_malware_attachment(part)
                        if result:
                            malware_reasons.extend(result)

            # Combine reasons
            all_reasons = phishing_reasons + malware_reasons
            if all_reasons:
                logging.warning(f"⚠ Suspicious: {subject} | Reasons: {', '.join(all_reasons)}")
                print(f"\n⚠ Suspicious Email: {subject}")
                for reason in all_reasons:
                    print(f"   - {reason}")
                # Move directly to Spam
                mail.copy(num, "[Gmail]/Spam")
                mail.store(num, "+FLAGS", "\\Deleted")
            else:
                logging.info(f"✅ Clean email: {subject}")
                print(f"✅ Clean email: {subject}")

        mail.expunge()
        mail.logout()
        print("\n✅ Scan complete. See email_threat_scan.log for details.")

    except Exception as e:
        logging.exception("Error during scan")
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    scan_inbox()
