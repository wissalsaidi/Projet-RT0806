import json
import base64
import os
import uuid
import threading
import paho.mqtt.client as mqtt
from cryptography.x509 import load_pem_x509_certificate
from crypto_utils import (
    chiffrer_aes, dechiffrer_aes, chiffrer_rsa,
    calculer_hash, verifier_signature, verifier_certificat
)

BROKER = "localhost"
PORT = 1883

# Identifiant unique pour cet acheteur (permet plusieurs acheteurs simultanes)
BUYER_ID = str(uuid.uuid4())[:8]

aes_key = None
catalogue = []
catalogue_pret = threading.Event()
confirmation_prete = threading.Event()


def _creer_client_mqtt(client_id: str):
    """Cree un client MQTT compatible paho-mqtt 1.x et 2.x."""
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


client = _creer_client_mqtt(f"acheteur_{BUYER_ID}")


def on_connect(cl, userdata, flags, rc):
    print(f"[Acheteur {BUYER_ID}] Connecte au broker MQTT")
    cl.subscribe(f"shop/handshake/cert/{BUYER_ID}")
    cl.subscribe(f"shop/catalogue/{BUYER_ID}")
    cl.subscribe(f"shop/confirmation/{BUYER_ID}")
    # Demande de connexion : le vendeur enverra son certificat en retour
    cl.publish("shop/handshake/request", json.dumps({"buyer_id": BUYER_ID}))
    print("[Acheteur] Demande de connexion envoyee au vendeur...")


def on_message(cl, userdata, msg):
    topic = msg.topic
    try:
        if topic == f"shop/handshake/cert/{BUYER_ID}":
            _handle_cert(msg.payload)
        elif topic == f"shop/catalogue/{BUYER_ID}":
            _handle_catalogue(msg.payload)
        elif topic == f"shop/confirmation/{BUYER_ID}":
            _handle_confirmation(msg.payload)
    except Exception as e:
        print(f"[Acheteur] Erreur traitement message: {e}")


def _handle_cert(payload):
    """Recoit le certificat X.509, le verifie, genere et envoie la cle AES."""
    global aes_key

    cert = load_pem_x509_certificate(payload)
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat du vendeur invalide ou expire !")
        return

    print("[Acheteur] Certificat X.509 du vendeur verifie OK")

    # Generation de la cle de session AES-256 (32 octets aleatoires)
    aes_key = os.urandom(32)

    # Chiffrement de la cle AES avec la cle publique RSA du vendeur (OAEP)
    cle_pub_vendeur = cert.public_key()
    aes_key_chiffree = chiffrer_rsa(aes_key, cle_pub_vendeur)

    client.publish(
        f"shop/handshake/key/{BUYER_ID}",
        base64.b64encode(aes_key_chiffree)
    )
    print("[Acheteur] Cle AES-256 envoyee (chiffree RSA-2048)")


def _handle_catalogue(payload):
    """Recoit, dechiffre et verifie le catalogue du vendeur."""
    global catalogue

    msg = json.loads(payload)

    # 1. Verification du certificat joint au message
    cert = load_pem_x509_certificate(msg["cert"].encode())
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat invalide dans le catalogue !")
        return

    # 2. Dechiffrement AES-256 avec la cle de session
    contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

    # 3. Verification de la signature RSA sur le hash SHA-1
    hash_calcule = calculer_hash(contenu)
    signature = base64.b64decode(msg["hash"])
    if not verifier_signature(hash_calcule, signature, cert.public_key()):
        print("[Acheteur] ALERTE : integrite du catalogue compromise !")
        return

    catalogue = json.loads(contenu)
    print("[Acheteur] Catalogue recu, dechiffre et verifie (SHA-1 OK)")
    catalogue_pret.set()


def _handle_confirmation(payload):
    """Recoit, dechiffre et affiche la confirmation de commande."""
    msg = json.loads(payload)

    cert = load_pem_x509_certificate(msg["cert"].encode())
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat invalide dans la confirmation !")
        return

    contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

    hash_calcule = calculer_hash(contenu)
    signature = base64.b64decode(msg["hash"])
    if not verifier_signature(hash_calcule, signature, cert.public_key()):
        print("[Acheteur] ALERTE : integrite de la confirmation compromise !")
        return

    confirmation = json.loads(contenu)
    print(f"\n{'='*45}")
    print(f"         CONFIRMATION DE COMMANDE")
    print(f"{'='*45}")
    print(f"  Statut    : {confirmation['statut']}")
    print(f"  Message   : {confirmation['message']}")
    print(f"  Reference : {confirmation['reference']}")
    print(f"{'='*45}\n")
    confirmation_prete.set()


def afficher_catalogue():
    print(f"\n{'='*45}")
    print(f"         CATALOGUE — BOUTIQUE MQTT")
    print(f"{'='*45}")
    for item in catalogue:
        print(f"  [{item['id']:2d}]  {item['nom']:<22} {item['prix']:>4} EUR")
    print(f"{'='*45}")


def main():
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(BROKER, PORT)
    client.loop_start()

    print("[Acheteur] En attente du catalogue...")
    if not catalogue_pret.wait(timeout=15):
        print("[Acheteur] Timeout — le vendeur ne repond pas (Mosquitto est-il lance ?)")
        client.loop_stop()
        return

    afficher_catalogue()

    # Saisie du choix utilisateur
    while True:
        try:
            choix = int(input("\nChoisissez un produit (1-10) : "))
            if 1 <= choix <= 10:
                break
            print("  Entrez un numero entre 1 et 10.")
        except ValueError:
            print("  Entrez un nombre valide.")

    produit = next(p for p in catalogue if p["id"] == choix)
    print(f"\n[Acheteur] Envoi de la commande : {produit['nom']} a {produit['prix']} EUR")

    # Chiffrement AES-256 de la commande + hash SHA-1 pour l'integrite
    commande_bytes = json.dumps(produit, ensure_ascii=False).encode()
    data_chiffre = chiffrer_aes(commande_bytes, aes_key)
    hash_msg = calculer_hash(commande_bytes)

    # L'acheteur n'a pas de cle privee : le hash est envoye brut (sans signature RSA)
    message = json.dumps({
        "data": base64.b64encode(data_chiffre).decode(),
        "hash": base64.b64encode(hash_msg).decode(),
    })
    client.publish(f"shop/commande/{BUYER_ID}", message)
    print("[Acheteur] Commande chiffree (AES-256) envoyee")

    if not confirmation_prete.wait(timeout=15):
        print("[Acheteur] Timeout — pas de confirmation recue")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
