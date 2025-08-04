# sync_cert

A Linux shell script that securely retrieves, validates, and installs a wildcard SSL certificate from AWS Secrets Manager. Ideal for EC2 instances using IAM roles.

## Files

- `sync_cert.sh` – The main certificate sync script
- `sync_cert.conf.example` – Example config with placeholders
- `.gitignore` – Protects sensitive and runtime files from being committed

## Setup

1. Copy and edit `sync_cert.conf.example` as `/etc/sync_cert.conf`
2. Ensure the VM has access to AWS Secrets Manager via IAM role
3. Run the script:

```bash
sudo ./sync_cert.sh

# sync_cert.sh – SSL Certificate Sync & Auto-Renew Script

This script automates the retrieval, validation, installation, and management of a wildcard SSL certificate (`*.yourdomain.com`) from AWS Secrets Manager. It is designed to be run via cron on Debian-based systems, integrates safely with nginx, and notifies administrators of important events.

---

## 📦 Features

- Fetches base64-encoded cert, key, and bundles from AWS Secrets Manager
- Validates Common Name (CN) and Subject Alternative Names (SANs)
- Checks certificate expiration and warns if ≤15 days left
- Logs fingerprint, issuer, and expiration date
- Installs new certs only if changed; backs up old versions
- Safely reloads nginx after testing its configuration
- Notifies admins by email on errors, warnings, and first-time installs
- Supports logrotate: 2 months plain logs, 10 months compressed
- Dynamic admin email configuration via `/etc/sync_cert.conf`

---

## 🛠️ What the Script Does

1. Fetches SSL certificate from AWS Secrets Manager
2. Decodes the base64 values into:
   - `yourdomain.com.crt`
   - `yourdomain.com.key`
   - `yourdomain.com.ca-bundle`
   - `ssl-bundle.crt`
3. Validates CN and SAN values
4. Logs:
   - SHA-256 fingerprint
   - Certificate issuer
   - Expiration date and days remaining
5. Sends email alerts if:
   - Certificate expired
   - Expiration ≤ 15 days
   - CN/SAN mismatch
   - First-time install (no certs found)
   - Nginx reload fails or config test fails
6. Installs new certs if changed and reloads nginx
7. Backs up previous cert files in `/etc/ssl/yourdomain.com/`
8. Cleans up temporary files in `/tmp/sync_cert`

---

## ⚠️ Exceptions and Edge Cases Handled

| Case                               | Behavior                                                   |
|------------------------------------|-------------------------------------------------------------|
| AWS Secret fetch fails             | Logs error, notifies admin, exits                           |
| Base64 decoding fails              | Logs error, notifies admin, exits                           |
| CN or SAN mismatch                 | Logs error, notifies admin, exits                           |
| Certificate already expired        | Logs error, notifies admin, exits                           |
| Certificate expires in ≤15 days    | Logs warning, sends email                                   |
| No existing certs in `$CERT_DIR`   | Writes new files, skips nginx reload, notifies admin        |
| Nginx reload fails                 | Logs error, notifies admin                                  |
| Nginx config test fails            | Skips reload, logs and emails admin                         |
| Cert and key unchanged             | No backup, no reload                                        |
| Temp dir left behind               | Always cleaned with `rm -rf`                                |

---

## 🔧 Configuration

### `/etc/sync_cert.conf` (optional)
Provide domain name, AWS secret name, recipient email(s), and admin email.
domain name and AWS secret name are MUST

```bash
# Example config
DOMAIN_NAME="yourdomain.com"
SECRET_NAME="your/aws/secretsmanager/ssl-cert"
EMAIL="noreply@example.com"
ADMIN_EMAIL="admin@example.com"
