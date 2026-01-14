#!/bin/sh
set -e

export VAULT_ADDR=${VAULT_ADDR:-http://0.0.0.0:8200}
export VAULT_TOKEN=${VAULT_DEV_ROOT_TOKEN_ID:-root}

echo "Attente de Vault..."
until curl -s ${VAULT_ADDR}/v1/sys/health >/dev/null 2>&1; do
  sleep 1
done
echo "Vault est up."

echo "Activation PKI Root..."
vault secrets enable -path=pki_root pki || true
vault secrets tune -max-lease-ttl=87600h pki_root

echo "Génération Root CA..."
vault write pki_root/root/generate/internal \
  common_name="MyRootCA" \
  ttl=87600h >/tmp/root_ca.json

vault write pki_root/config/urls \
  issuing_certificates="${VAULT_ADDR}/v1/pki_root/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/pki_root/crl"

echo "Activation PKI SubCA..."
vault secrets enable -path=pki_sub pki || true
vault secrets tune -max-lease-ttl=43800h pki_sub

echo "Génération CSR SubCA..."
vault write -format=json pki_sub/intermediate/generate/internal \
  common_name="MySubCA" \
  ttl=43800h > /tmp/subca_csr.json

CSR=$(jq -r '.data.csr' /tmp/subca_csr.json)

echo "Signature SubCA par la Root..."
SIGNED_SUBCA=$(vault write -format=json pki_root/root/sign-intermediate \
  csr="$CSR" \
  format=pem_bundle \
  ttl=43800h)

CERT=$(echo "$SIGNED_SUBCA" | jq -r '.data.certificate')

echo "$CERT" > /tmp/subca_cert.pem

echo "Import du cert SubCA..."
vault write pki_sub/intermediate/set-signed certificate=@/tmp/subca_cert.pem

vault write pki_sub/config/urls \
  issuing_certificates="${VAULT_ADDR}/v1/pki_sub/ca" \
  crl_distribution_points="${VAULT_ADDR}/v1/pki_sub/crl"

echo "Création d'un rôle pour les endpoints..."
vault write pki_sub/roles/endpoints \
  allowed_domains="example.local" \
  allow_subdomains=true \
  max_ttl="720h"

echo "PKI Root + SubCA configurés."
echo "Pour générer un cert endpoint :"
echo "  vault write pki_sub/issue/endpoints common_name=\"host1.example.local\" ttl=\"24h\""
