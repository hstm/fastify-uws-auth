#!/bin/bash

# Generate RSA key pair for RS256 JWT signing
# Private key: 4096 bits for enhanced security
# Public key: Extracted from private key

set -e

KEYS_DIR="./keys"

# Create keys directory if it doesn't exist
mkdir -p "$KEYS_DIR"

echo "Generating RSA key pair..."

# Generate private key (4096 bits)
openssl genrsa -out "$KEYS_DIR/private.pem" 4096

# Extract public key from private key
openssl rsa -in "$KEYS_DIR/private.pem" -pubout -out "$KEYS_DIR/public.pem"

# Set appropriate permissions
chmod 600 "$KEYS_DIR/private.pem"
chmod 644 "$KEYS_DIR/public.pem"

echo "✓ RSA key pair generated successfully!"
echo "  Private key: $KEYS_DIR/private.pem"
echo "  Public key:  $KEYS_DIR/public.pem"
echo ""
echo "⚠️  WARNING: Keep private.pem secure and never commit it to version control!"
