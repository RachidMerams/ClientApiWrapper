from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
import os
import requests
import subprocess
import tempfile
import re
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


#A adapter en exportant UNIQUEMENT
VAULT_ADDR = os.environ["VAULT_ADDR"]
VAULT_TOKEN = os.environ["VAULT_TOKEN"]
VAULT_NAMESPACE = os.environ["VAULT_NAMESPACE"]
PKI_PATH = os.environ["PKI_PATH"]
HEADERS = {
					"X-Vault-Token": VAULT_TOKEN,
					"X-Vault-Namespace": VAULT_NAMESPACE}

#print("[DEBUG] Vault server addr set to => "+ VAULT_ADDR)
#print("[DEBUG] Full addr => "+VAULT_ADDR+PKI_PATH)

app = FastAPI()

@app.get("/")
def serve_swagger():
    return RedirectResponse(url="/docs")
    

# ------------------------------
# Vault helpers functions
# ------------------------------

def vault_list_certs():
    url = f"{VAULT_ADDR}{PKI_PATH}/certs"
    r = requests.request("LIST", url, headers=HEADERS, verify=False)
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Vault LIST error: {r.text}")
    return r.json()["data"]["keys"]


def vault_get_cert(serial):
    url = f"{VAULT_ADDR}{PKI_PATH}/cert/{serial}"
    r = requests.get(url, headers=HEADERS, verify=False)
    if r.status_code != 200:
        raise HTTPException(status_code=502, detail=f"Vault GET error: {r.text}")
    return r.json()["data"]


# ------------------------------
# OpenSSL parsing
# ------------------------------

def parse_cert_with_openssl(pem):

    # Analyse d'un cert avec Openssl, on recupere les datas qui nous interessent on format et on renvoi le JSON

    #On creer le tmp file utilisé localement pour ecrire et lire le cert
    with tempfile.NamedTemporaryFile(delete=True) as tmp:
        tmp.write(pem.encode())
        tmp.flush()

    #On lis le temp file (qui est en fait le cert a ce stade)
        result = subprocess.run(
            ["openssl", "x509", "-in", tmp.name, "-noout", "-text"],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise Exception(f"OpenSSL error: {result.stderr}")

        text = result.stdout
        
        #On trie et recup les infos (avec la meme regex sauf pour Serial psq hexadecimal, on va pas se prendre la tete ca fonctionne) 
        issuer = re.search(r"Issuer:\s*(.*)", text)
        subject = re.search(r"Subject:\s*(.*)", text)
        serial = re.search(r"Serial Number:\s*([0-9A-F:]+)", text)
        not_before = re.search(r"Not Before:\s*(.*)", text)
        not_after = re.search(r"Not After :\s*(.*)", text)
        san = re.search(r"X509v3 Subject Alternative Name:\s*\n\s*(.*)", text)

        # Extraction de l'OU dans le Subject
        ou_match = re.search(r"OU\s*=\s*([^,/]+)", subject.group(1)) if subject else None
        ou_value = ou_match.group(1).strip() if ou_match else None

        #On return un json tout beau tout propre
        return {
            "issuer": issuer.group(1).strip() if issuer else None,
            "subject": subject.group(1).strip() if subject else None,
            "serial_x509": serial.group(1).strip() if serial else None,
            "not_before": not_before.group(1).strip() if not_before else None,
            "not_after": not_after.group(1).strip() if not_after else None,
            "sans": san.group(1).strip() if san else None,
            "ou": ou_value if ou_value else None
        }


# ------------------------------
# API endpoint
# ------------------------------

#Vrai endpoint exposé de l'API, le seul autiliser (pour le moment, faudra aussi l'enrichir)

@app.get("/certificates")
def list_certificates():
    serials = vault_list_certs()
    certs = []

    for serial in serials:
        data = vault_get_cert(serial)
        pem = data["certificate"]

        parsed = parse_cert_with_openssl(pem)

        certs.append({
            "vault_serial": serial,
            "role": parsed["ou"],  # <-- OU devient "role"
            "issuer": parsed["issuer"],
            "subject": parsed["subject"],
            "serial_x509": parsed["serial_x509"],
            "not_before": parsed["not_before"],
            "not_after": parsed["not_after"],
            "sans": parsed["sans"],
        })

    return {
        "count": len(certs),
        "certificates": certs
    }
