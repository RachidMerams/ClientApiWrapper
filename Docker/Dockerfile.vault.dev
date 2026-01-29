FROM hashicorp/vault:1.19

# On ajoute curl et jq pour les scripts
USER root
RUN apk add --no-cache curl jq

# Variables par défaut (tu peux les override au run)
ENV VAULT_ADDR=http://0.0.0.0:8200 \
    VAULT_DEV_ROOT_TOKEN_ID=root \
    VAULT_TOKEN=root \
    VAULT_SKIP_VERIFY=true

# Script d'init
COPY init-pki.sh /usr/local/bin/init-pki.sh
RUN chmod +x /usr/local/bin/init-pki.sh

# Entrypoint : on lance Vault dev puis on configure PKI
ENTRYPOINT ["/bin/sh", "-c", "vault server -dev -dev-listen-address=0.0.0.0:8200 -dev-root-token-id=${VAULT_DEV_ROOT_TOKEN_ID} & /usr/local/bin/init-pki.sh && wait"]
