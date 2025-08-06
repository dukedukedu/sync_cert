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
# REQUIRED_IAM_ROLE="IAM_Role_Name"
# AZURE_KEY_VAULT_NAME="your-key-vault-name"
# =====================


# Load config
CONFIG_FILE="/etc/sync_cert.conf"
[ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE"

# Detect platform
detect_platform() {
  # Try AWS IMDSv2
  if TOKEN=$(curl -s --fail --connect-timeout 1 -X PUT \
      "http://169.254.169.254/latest/api/token" \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 60"); then

    if curl -s --fail --connect-timeout 1 \
        -H "X-aws-ec2-metadata-token: $TOKEN" \
        http://169.254.169.254/latest/meta-data/ >/dev/null; then
      echo "aws"
      return
    fi
  fi

  # Fallback to AWS IMDSv1
  if curl -s --fail --connect-timeout 1 \
       http://169.254.169.254/latest/meta-data/ >/dev/null; then
    echo "aws"
    return
  fi

  # Try Azure
  if curl -s --fail -H "Metadata:true" --connect-timeout 1 \
       "http://169.254.169.254/metadata/instance?api-version=2021-02-01" \
       -o /dev/null; then
    echo "azure"
    return
  fi

  # Unknown
  echo "unknown"
}

PLATFORM=$(detect_platform)

# Defaults
SECRET_NAME="${SECRET_NAME:-your/aws/secret/name}"
CERT_DIR="/etc/ssl/${DOMAIN_NAME:-yourdomain.com}"
TMP_DIR="/tmp/sync_cert"
LOG_DIR="/var/log/sync_cert"
LOG_FILE="$LOG_DIR/sync_cert.log"
ERR_FILE="$LOG_DIR/sync_cert.err"
ARCHIVE_DIR="$LOG_DIR/archive"
EMAIL="${EMAIL:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
AZURE_KEY_VAULT_NAME="${AZURE_KEY_VAULT_NAME:-}"

AWS_CMD=$(command -v aws || true)
AZ_CMD=$(command -v az || true)
JQ_CMD=$(command -v jq || true)

mkdir -p "$LOG_DIR" "$CERT_DIR" "$TMP_DIR" "$ARCHIVE_DIR"
chown root:adm "$ARCHIVE_DIR"

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

  if [[ -z "$EMAIL" || -z "$ADMIN_EMAIL" ]]; then
    log "[INFO] Skipping email (missing EMAIL or ADMIN_EMAIL)."
    return 0
  fi
  if [[ "$EMAIL" == "noreply@example.com" || "$ADMIN_EMAIL" == "admin@example.com" ]]; then
    log "[INFO] Skipping email (EMAIL or ADMIN_EMAIL still default values)."
    return 0
  fi
  if ! command -v mail >/dev/null 2>&1; then
    log_error "'mail' command not available. Cannot send email."
    return 1
  fi

  echo -e "Host: $(hostname -f)\n\n$message" | mail -s "[$(hostname -f)] $subject" \
    -a "From: SSL Certificate Update <$EMAIL>" \
    -a "X-Priority: 1 (Highest)" \
    -a "Importance: High" \
    "$ADMIN_EMAIL"
  log "[INFO] Sent notification: $subject"
}

HOSTNAME_FQDN=$(hostname -f 2>/dev/null)
[[ -z "$HOSTNAME_FQDN" || "$HOSTNAME_FQDN" == "(none)" ]] && \
  HOSTNAME_FQDN=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null)
HOSTNAME_FQDN=${HOSTNAME_FQDN:-unknown-host}

if [[ "$PLATFORM" == "unknown" ]]; then
  log_error "Unknown cloud platform. Cannot proceed."
  notify_admin "Unknown cloud platform detected on $HOSTNAME_FQDN. SSL certificate update was unfinished and stopped." \
               "Unknown Platform - SSL Sync Halted"
  exit 1
fi

log "[INFO] Detected platform: $PLATFORM"

if [[ "$PLATFORM" == "aws" ]]; then
  REGION=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document 2>/dev/null | jq -r '.region')
  REGION=${AWS_REGION:-${REGION:-us-east-1}}
  REQUIRED_IAM_ROLE="${REQUIRED_IAM_ROLE:-IAM_Role_Name}"

  IAM_ROLE_ARN=$(curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/iam/info | jq -r .InstanceProfileArn || echo "")
  IAM_ROLE_NAME=$(basename "$IAM_ROLE_ARN")

  if [[ "$REQUIRED_IAM_ROLE" != "IAM_Role_Name" ]]; then
    if [[ -z "$IAM_ROLE_NAME" ]]; then
      log_error "No IAM role found or metadata API is unavailable."
      notify_admin "IAM role check failed. No IAM role found on $HOSTNAME_FQDN." "IAM Role Missing"
      exit 1
    elif [[ "$IAM_ROLE_NAME" != "$REQUIRED_IAM_ROLE" ]]; then
      log_error "IAM role mismatch. Expected: $REQUIRED_IAM_ROLE, Got: $IAM_ROLE_NAME"
      notify_admin "IAM role mismatch. Expected: $REQUIRED_IAM_ROLE, Got: $IAM_ROLE_NAME" "IAM Role Mismatch"
      exit 1
    fi
    log "IAM role verified: $IAM_ROLE_NAME"
  else
    log "[INFO] IAM role validation skipped (default value used)"
  fi
else
  log "[INFO] Skipping IAM role check (non-AWS)"
fi

declare -A FILE_MAP=(
  ["cert"]="${DOMAIN_NAME}.crt"
  ["key"]="${DOMAIN_NAME}.key"
  ["chain"]="${DOMAIN_NAME}.ca-bundle"
  ["fullchain"]="ssl-bundle.crt"
)

if [[ "$PLATFORM" == "aws" ]]; then
  log "[INFO] Fetching secrets from AWS..."
  SECRET=$($AWS_CMD secretsmanager get-secret-value \
    --secret-id "$SECRET_NAME" \
    --region "$REGION" \
    --query SecretString \
    --output text 2>>"$ERR_FILE")

  if [[ -z "$SECRET" ]]; then
    log_error "AWS Secrets Manager fetch failed."
    notify_admin "Could not retrieve secret from AWS." "AWS Secret Fetch Error"
    exit 1
  fi

  for key in "${!FILE_MAP[@]}"; do
    echo "$SECRET" | $JQ_CMD -r ".${key}" | base64 -d > "$TMP_DIR/${FILE_MAP[$key]}" 2>/dev/null || {
      log_error "Failed to decode AWS secret for key: $key"
      notify_admin "AWS secret decoding failed for key: $key" "AWS Secret Decode Error"
      rm -rf "$TMP_DIR"
      exit 1
    }
  done

elif [[ "$PLATFORM" == "azure" ]]; then
  log "[INFO] Fetching secrets from Azure Key Vault: $AZURE_KEY_VAULT_NAME"
  
  az login --identity >/dev/null 2>&1 || {
    log_error "Azure CLI login with managed identity failed."
    notify_admin "Azure CLI login failed on $HOSTNAME_FQDN" "Azure Login Failed"
    exit 1
  }
  
  for key in "${!FILE_MAP[@]}"; do
    secret=$($AZ_CMD keyvault secret show \
      --vault-name "$AZURE_KEY_VAULT_NAME" \
      --name "$key" \
      --query value -o tsv 2>>"$ERR_FILE" || echo "")

    if [[ -z "$secret" ]]; then
      log_error "Missing or empty Azure secret [$key]"
      notify_admin "Azure secret [$key] missing or empty in vault: $AZURE_KEY_VAULT_NAME" "Azure Secret Error"
      rm -rf "$TMP_DIR"
      exit 1
    fi

    echo "$secret" | base64 -d > "$TMP_DIR/${FILE_MAP[$key]}" 2>/dev/null || {
      log_error "Azure secret base64 decode failed for key: $key"
      notify_admin "Azure secret decoding failed for key: $key" "Azure Secret Decode Error"
      rm -rf "$TMP_DIR"
      exit 1
    }
  done
fi

validate_cn() {
  local cert_file="$1"
  local expected_cn="*.${DOMAIN_NAME}"
  local cn=$(openssl x509 -noout -subject -in "$cert_file" | sed -n 's/^.*CN *= *\([^,\/]*\).*$/\1/p')
  [[ "$cn" != "$expected_cn" ]] && {
    log_error "CN mismatch. Expected: $expected_cn, Got: $cn"
    notify_admin "Certificate CN mismatch: $cn" "SSL CN Mismatch"
    return 1
  }
  log "CN verified: $cn"
}

validate_san() {
  local cert_file="$1"
  local san=$(openssl x509 -in "$cert_file" -noout -text | awk '/Subject Alternative Name:/{getline; print}' | sed 's/DNS://g' | tr -d ' ')
  [[ "$san" != *"*.$DOMAIN_NAME"* || "$san" != *"$DOMAIN_NAME"* ]] && {
    log_error "Missing SAN entries in cert: $san"
    notify_admin "SAN mismatch: expected *.$DOMAIN_NAME and $DOMAIN_NAME" "SSL SAN Mismatch"
    return 1
  }
  log "SAN verified: $san"
}

cert_file="$TMP_DIR/${FILE_MAP["cert"]}"
validate_cn "$cert_file" || exit 1
validate_san "$cert_file" || exit 1

EXPIRY_DATE=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY_DATE" +%s)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))

log "Cert expires on $EXPIRY_DATE ($DAYS_LEFT days left)"
[[ $DAYS_LEFT -lt 0 ]] && {
  log_error "Certificate already expired"
  notify_admin "SSL certificate expired on $EXPIRY_DATE" "SSL Expired"
  rm -rf "$TMP_DIR"
  exit 1
}
[[ $DAYS_LEFT -le 15 ]] && {
  log "[WARNING] Certificate expiring in $DAYS_LEFT days"
  notify_admin "SSL certificate expiring soon: $DAYS_LEFT days left" "SSL Expiry Warning"
}

cert_changed=false
for key in cert key; do
  src="$TMP_DIR/${FILE_MAP[$key]}"
  dst="$CERT_DIR/${FILE_MAP[$key]}"
  [[ ! -f "$dst" ]] || ! cmp -s "$src" "$dst" && cert_changed=true
done

if $cert_changed; then
  TIMESTAMP=$(date -u '+%Y%m%dT%H%M%SZ')
  log "Installing new cert and backing up old files"
  for key in "${!FILE_MAP[@]}"; do
    src="$TMP_DIR/${FILE_MAP[$key]}"
    dst="$CERT_DIR/${FILE_MAP[$key]}"
    [[ -f "$dst" ]] && cp "$dst" "$CERT_DIR/${FILE_MAP[$key]}.$TIMESTAMP"
    cp "$src" "$dst"
    chmod 640 "$dst"
    chown root:adm "$dst"
  done

  if nginx -t; then
    systemctl reload nginx && sleep 3
    systemctl is-active --quiet nginx && log "Nginx reloaded successfully" || {
      log_error "Nginx failed after reload"
      notify_admin "Nginx reload failed after cert update" "Nginx Reload Failed"
    }
  else
    log_error "Nginx config test failed"
    notify_admin "Nginx config test failed. Cert installed but not applied." "Nginx Config Test Failed"
  fi
else
  log "No changes detected in certificate. Skipping reload."
fi

rm -rf "$TMP_DIR"
