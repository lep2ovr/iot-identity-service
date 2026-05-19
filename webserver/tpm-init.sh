#!/bin/bash
set -Eeuo pipefail

SNAP_NAME="azure-iot-identity"
APP_NAME="tpm2-webserver"
HANDLE="0x81010004" # With handle '0x81000001' it will not work because there is already a key there

CERTSTORE="$SNAP_COMMON/package-certificates/$SNAP_NAME/$APP_NAME"
KEY_DIR="$CERTSTORE/own/private"
CRT_DIR="$CERTSTORE/own/certs"
LOG_DIR="$SNAP_COMMON/log"
LOG_FILE="$LOG_DIR/$APP_NAME.log"

OPENSSL_CNF="$SNAP/usr/bin/csr.cnf"
TPM2KEY_PRIVATE="$KEY_DIR/webserver.hsm"
TPM2KEY_PUBLIC="$KEY_DIR/webserver.pub"
TPM2KEY_CONTEXT="$KEY_DIR/webserver.ctx"
PUB_PEM="$KEY_DIR/webserver_pub.pem"
CSR="$CRT_DIR/webserver.csr"

# $TPM2_SRK_PARENT is loaded from envvars file and should point to the SRK primary key context, e.g. "0x81000001"

mkdir -p "$CERTSTORE/ca" "$KEY_DIR" "$CRT_DIR" "$CERTSTORE/rejected/private" "$CERTSTORE/rejected/certs" "$CERTSTORE/trusted/private" "$CERTSTORE/trusted/certs" "$LOG_DIR"

# Mirror logs to file and snap logs
exec > >(tee -a "$LOG_FILE") 2>&1

log() {
    echo "[$(date -Iseconds)] $*"
}

log "Starting $APP_NAME"

# Load ctrlX TPM env if available
if [ -f "$SNAP_DATA/system-configuration/certificate-manager/tpm2/envvars" ]; then
    . "$SNAP_DATA/system-configuration/certificate-manager/tpm2/envvars"
    log "Loaded TPM envvars from system-configuration content interface"
else
    log "ERROR: TPM envvars file not found"
    exit 1
fi

# Keep OpenSSL TPM provider aligned with tpm2-tools TCTI
export TPM2OPENSSL_TCTI="${TPM2OPENSSL_TCTI:-${TPM2TOOLS_TCTI:-}}"
if [ -z "${TPM2OPENSSL_TCTI:-}" ]; then
    log "ERROR: TPM2OPENSSL_TCTI is empty"
    exit 1
fi

log "Using TCTI: $TPM2OPENSSL_TCTI"

# Find OpenSSL modules dir that contains tpm2 provider
OPENSSL_MODULES_DIR="$(find "$SNAP/usr/lib" -type f -name tpm2.so -printf '%h\n' | head -n1 || true)"
if [ -z "$OPENSSL_MODULES_DIR" ]; then
    log "ERROR: Could not find tpm2 OpenSSL provider module"
    exit 1
fi

export OPENSSL_MODULES="$OPENSSL_MODULES_DIR"
log "OPENSSL_MODULES=$OPENSSL_MODULES"

# Verify TPM access
if ! tpm2_getcap properties-fixed >/dev/null 2>&1; then
    log "ERROR: TPM is not reachable from this snap. Check interface connections."
    exit 1
fi

log "TPM access OK"

# Create persistent TPM-bound key only if handle does not exist
if tpm2_readpublic -Q -c "$HANDLE" >/dev/null 2>&1; then
    log "Persistent key already exists at handle $HANDLE"
else
    # log "Creating TPM primary key"
    # tpm2_createprimary -Q -C o -g sha256 -G rsa -c "$PRIMARY_CONTEXT"
    log "Evicting any existing key at handle $HANDLE"
    tpm2_evictcontrol -Q -c "$HANDLE" || true

    log "Creating TPM child key with non-exportable TPM-bound attributes using TPM2_SRK_PARENT as parent"
    tpm2_create -Q -C "$TPM2_SRK_PARENT" -G rsa2048:rsassa-sha256 -u "$TPM2KEY_PUBLIC" -r "$TPM2KEY_PRIVATE" -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign"

    log "Loading child key to context"
    tpm2_load -Q \
        -C "$TPM2_SRK_PARENT" \
        -u "$TPM2KEY_PUBLIC" \
        -r "$TPM2KEY_PRIVATE" \
        -c "$TPM2KEY_CONTEXT"

    log "Persisting key at handle $HANDLE"
    tpm2_evictcontrol -Q -C o -c "$HANDLE" || true
    tpm2_evictcontrol -Q -C o -c "$TPM2KEY_CONTEXT" "$HANDLE"
fi

log "Exporting public key from handle"
tpm2_readpublic -c "$HANDLE" -f pem -o "$PUB_PEM"

log "Generating CSR from TPM handle"
openssl req \
    -provider tpm2 \
    -provider default \
    -propquery '?provider=tpm2' \
    -new \
    -key "handle:$HANDLE" \
    -out "$CSR" \
    -config "$OPENSSL_CNF"

log "CSR generated at: $CSR"

cat "$CSR"
openssl req -in "$CSR" -noout -text

log "tpm-init done; CSR at $CSR"

exit 0
