import requests
import json

VAULT_BASE_URL="http://127.0.0.1:8200"
PKI_PATH="/v1/pki_sub"

VAULT_TOKEN="root" #Attention il faudra que je vire ca pour le vrai script chez Suez
VAULT_NAMESPACE="" #La on s'en fout c'est en mode dev mais attention aussi en prod chez le client

HEADERS = {"X-Vault-Token": VAULT_TOKEN}

r = requests.request('LIST', VAULT_BASE_URL+PKI_PATH+"/certs", headers=HEADERS) #devrait lister les certs

print(json.dumps(r.json(), indent=4, sort_keys=True))

serials = r.json()['data']['keys']

print(serials)


for serial in serials:
    print(serial)
    req = requests.get(VAULT_BASE_URL+PKI_PATH+"/cert/"+serial)
    print(json.dumps(req.json(), indent=4, sort_keys=True))
