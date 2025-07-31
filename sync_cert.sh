#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# =====================
# sync_cert.sh
# =====================

# =====================
# sample /etc/sync_cert.conf
# /etc/sync_cert.conf

# DOMAIN_NAME="yourdomain.com"
# SECRET_NAME="your/aws/secretsmanager/ssl-cert"
# EMAIL="noreply@example.com"
# ADMIN_EMAIL="admin@example.com"
# =====================

# Load optional config
[ -f /etc/sync_cert.conf ] && source /etc/sync_cert.conf

# CONFIGURATION (fallbacks if config not loaded)
SECRET_NAME="${SECRET_NAME:-your/aws/secret/name}"
CERT_DIR="/etc/ssl/${DOMAIN_NAME:-yourdomain.com}"
TMP_DIR="/tmp/sync_cert"
LOG_DIR="/var/log/sync_cert"
LOG_FILE="$LOG_DIR/sync_cert.log"
ERR_FILE="$LOG_DIR/sync_cert.err"
ARCHIVE_DIR="$LOG_DIR/archive"
EMAIL="${EMAIL:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"

AWS_CMD=$(which aws)
JQ_CMD=$(which jq)

# REGION DETECTION
REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null | jq -r '.region')
REGION=${REGION:-us-east-1}
REGION=${AWS_REGION:-$REGION}

# HOSTNAME
HOSTNAME_FQDN=$(hostname -f 2>/dev/null)
if [[ -z "$HOSTNAME_FQDN" || "$HOSTNAME_FQDN" == "(none)" ]]; then
  HOSTNAME_FQDN=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
fi
HOSTNAME_FQDN=${HOSTNAME_FQDN:-unknown-host}

# SETUP
mkdir -p "$LOG_DIR" "$CERT_DIR" "$TMP_DIR" "$ARCHIVE_DIR"
chown root:adm "$ARCHIVE_DIR"

# LOGGING
log() {
  local msg="[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] $1"
  echo "$msg" | tee -a "$LOG_FILE"
}

log_error() {
  local msg="[$(date -u '+%Y-%m-%d %H:%M:%S UTC')] ERROR: $1"
  echo "$msg" | tee -a "$LOG_FILE"
  echo "$msg" >> "$ERR_FILE"
}

notify_admin() {
  local message="$1"
  local subject="$2"

  if [[ -z "${EMAIL:-}" || -z "${ADMIN_EMAIL:-}" ]]; then
    log "[INFO] Skipping email notification because EMAIL or ADMIN_EMAIL is not set."
    return 0
  fi

  echo -e "Host: $HOSTNAME_FQDN\n\n$message" | mail -s "[$HOSTNAME_FQDN] $subject" \
    -a "From: SSL Certificate Update <$EMAIL>" \
    -a "X-Priority: 1 (Highest)" \
    -a "Importance: High" \
    "$ADMIN_EMAIL"
}


validate_cn() {
  local cert_file="$1"
  local expected_cn="*.${DOMAIN_NAME}"
  local cert_cn
  cert_cn=$(openssl x509 -noout -subject -in "$cert_file" | sed -n 's/^.*CN[[:space:]]*=[[:space:]]*\([^,\/]*\).*$/\1/p')

  if [[ "$cert_cn" != "$expected_cn" ]]; then
    log_error "CN mismatch: expected '$expected_cn', got [$cert_cn]"
    notify_admin "Certificate CN mismatch. Expected: $expected_cn, Got: [$cert_cn]" "SSL Certificate CN Mismatch"
    return 1
  fi
  log "CN verified: [$cert_cn]"
}

validate_san() {
  local cert_file="$1"
  local san_list
  san_list=$(openssl x509 -in "$cert_file" -noout -text | awk '/Subject Alternative Name:/{getline; print}' | sed 's/DNS://g' | tr -d ' ')

  if [[ "$san_list" != *"*.$DOMAIN_NAME"* ]] || [[ "$san_list" != *"$DOMAIN_NAME"* ]]; then
    log_error "Missing expected SAN entries. Found: [$san_list]"
    notify_admin "Expected SANs (*.$DOMAIN_NAME, $DOMAIN_NAME) not found in certificate. Found: [$san_list]" "SSL Certificate SAN Mismatch"
    return 1
  fi
  log "SAN entries verified: [$san_list]"
}

# FETCH SECRET
SECRET=$($AWS_CMD secretsmanager get-secret-value \
  --secret-id "$SECRET_NAME" \
  --region "$REGION" \
  --query SecretString \
  --output text 2>>"$ERR_FILE")

if [ $? -ne 0 ] || [[ -z "$SECRET" ]]; then
  log_error "Failed to retrieve secret from AWS."
  notify_admin "Failed to retrieve SSL secret from AWS Secrets Manager (region: $REGION)." "Cert Sync Error"
  exit 1
fi

declare -A FILE_MAP=(
  ["cert"]="${DOMAIN_NAME}.crt"
  ["key"]="${DOMAIN_NAME}.key"
  ["chain"]="${DOMAIN_NAME}.ca-bundle"
  ["fullchain"]="ssl-bundle.crt"
)

for key in "${!FILE_MAP[@]}"; do
  echo "$SECRET" | $JQ_CMD -r ".${key}" | base64 -d > "$TMP_DIR/${FILE_MAP[$key]}" 2>/dev/null
  if [ $? -ne 0 ]; then
    log_error "Failed to decode $key."
    notify_admin "Failed to decode $key from secret." "Cert Sync Error"
    rm -rf "$TMP_DIR"
    exit 1
  fi
done

cert_file="$TMP_DIR/${FILE_MAP["cert"]}"
validate_cn "$cert_file" || exit 1
validate_san "$cert_file" || exit 1

EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

FINGERPRINT=$(openssl x509 -noout -fingerprint -sha256 -in "$cert_file" | cut -d= -f2)
ISSUER=$(openssl x509 -noout -issuer -in "$cert_file" | sed 's/^issuer= //')

log "Certificate fingerprint (SHA-256): $FINGERPRINT"
log "Certificate issuer: $ISSUER"
log "Certificate expiry: $EXPIRY_DATE ($DAYS_LEFT days left)"

if [[ $DAYS_LEFT -lt 0 ]]; then
  log_error "Certificate already expired on $EXPIRY_DATE"
  notify_admin "Certificate already expired on $EXPIRY_DATE" "SSL Certificate Expired"
  rm -rf "$TMP_DIR"
  exit 1
elif [[ $DAYS_LEFT -le 15 ]]; then
  log "[WARNING] Certificate is expiring soon ($DAYS_LEFT days left)."
  notify_admin "The SSL certificate is valid but will expire in $DAYS_LEFT days." "SSL Certificate Expiration Warning"
fi

missing_all=true
for key in "${!FILE_MAP[@]}"; do
  if [[ -f "$CERT_DIR/${FILE_MAP[$key]}" ]]; then
    missing_all=false
    break
  fi
done

if $missing_all; then
  TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
  log "[WARNING] No existing certificate files found in $CERT_DIR."
  log "[INFO] Installing new certificate files, but nginx will NOT be reloaded automatically."

  for key in "${!FILE_MAP[@]}"; do
    src="$TMP_DIR/${FILE_MAP[$key]}"
    dst="$CERT_DIR/${FILE_MAP[$key]}"
    cp "$src" "$dst"
    chmod 640 "$dst"
    chown root:adm "$dst"
  done

  notify_admin "New certificate files installed at $CERT_DIR on $HOSTNAME_FQDN.\n\nNo existing certs were detected, so nginx was NOT reloaded. Please verify configuration and reload manually if appropriate." \
               "SSL Certificate Installed (Manual Reload Required)"

  rm -rf "$TMP_DIR"
  exit 0
fi

cert_changed=false
for key in cert key; do
  src="$TMP_DIR/${FILE_MAP[$key]}"
  dst="$CERT_DIR/${FILE_MAP[$key]}"
  if [[ ! -f "$dst" ]] || ! cmp -s "$src" "$dst"; then
    cert_changed=true
    break
  fi
done

if $cert_changed; then
  TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
  log "Installing new certificate. Backing up old files to $CERT_DIR."

  for key in "${!FILE_MAP[@]}"; do
    src="$TMP_DIR/${FILE_MAP[$key]}"
    dst="$CERT_DIR/${FILE_MAP[$key]}"
    [[ -f "$dst" ]] && cp "$dst" "$CERT_DIR/${FILE_MAP[$key]}.$TIMESTAMP"
    cp "$src" "$dst"
    chmod 640 "$dst"
    chown root:adm "$dst"
  done

  log "Running nginx config test..."
  if nginx -t; then
    systemctl reload nginx
    sleep 3
    if systemctl is-active --quiet nginx; then
      log "Nginx successfully reloaded with new certificate."
    else
      log_error "Nginx reload failed. Please check nginx status."
      notify_admin "Nginx reload failed after cert install." "Nginx Reload Error"
    fi
  else
    log_error "Nginx config test failed. Skipping reload."
    notify_admin "Nginx config test failed. Cert installed but not reloaded." "Nginx Test Error"
  fi
else
  log "Certificate and key unchanged. No reload necessary."
fi

rm -rf "$TMP_DIR"
