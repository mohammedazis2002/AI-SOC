#!/bin/bash
# Generate self-signed SSL certificates for development

SSL_DIR="infra/docker/nginx/ssl"
mkdir -p "$SSL_DIR"

echo "Ì¥ê Generating self-signed SSL certificate..."

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/key.pem" \
    -out "$SSL_DIR/cert.pem" \
    -subj "/C=US/ST=State/L=City/O=SOAR/OU=IT/CN=localhost"

chmod 644 "$SSL_DIR/cert.pem"
chmod 600 "$SSL_DIR/key.pem"

echo "‚úÖ SSL certificates generated successfully!"
echo "Ì≥Å Certificate: $SSL_DIR/cert.pem"
echo "Ì¥ë Private key: $SSL_DIR/key.pem"
echo ""
echo "‚ö†Ô∏è  Note: These are self-signed certificates for development only."
echo "   For production, use proper SSL certificates from a CA."
