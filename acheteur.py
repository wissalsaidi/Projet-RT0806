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

# Génère un identifiant unique pour cet acheteur à chaque lancement.
# Permet à plusieurs acheteurs de tourner en même temps sans se mélanger.
# Exemple : "a3f9b12c"
BUYER_ID = str(uuid.uuid4())[:8]

# Clé AES de session (générée pendant le handshake, utilisée ensuite pour tout chiffrer)
aes_key = None

# Liste des produits reçus du vendeur (remplie après déchiffrement du catalogue)
catalogue = []

# Ces deux "événements" servent à synchroniser les étapes :
# on attend que le catalogue soit prêt avant de demander à l'utilisateur de choisir,
# et on attend la confirmation avant de quitter.
catalogue_pret = threading.Event()
confirmation_prete = threading.Event()


def _creer_client_mqtt(client_id: str):
    # Compatibilité entre paho-mqtt version 1.x et 2.x
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


client = _creer_client_mqtt(f"acheteur_{BUYER_ID}")


def on_connect(cl, userdata, flags, rc):
    print(f"[Acheteur {BUYER_ID}] Connecte au broker MQTT")
    # S'abonne uniquement aux topics qui nous concernent (avec notre buyer_id)
    # → les messages des autres acheteurs ne nous parviennent pas
    cl.subscribe(f"shop/handshake/cert/{BUYER_ID}")
    cl.subscribe(f"shop/catalogue/{BUYER_ID}")
    cl.subscribe(f"shop/confirmation/{BUYER_ID}")
    # Lance le handshake : envoie notre identifiant au vendeur
    cl.publish("shop/handshake/request", json.dumps({"buyer_id": BUYER_ID}))
    print("[Acheteur] Demande de connexion envoyee au vendeur...")


def on_message(cl, userdata, msg):
    # Routage des messages reçus vers la bonne fonction selon le topic
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
    # On reçoit le certificat X.509 du vendeur.
    # Étape 1 : on vérifie qu'il est valide (non expiré, signature correcte).
    # Étape 2 : on génère notre clé AES de session.
    # Étape 3 : on chiffre cette clé AES avec la clé publique RSA du vendeur
    #            et on l'envoie → seul le vendeur pourra la déchiffrer.
    global aes_key

    cert = load_pem_x509_certificate(payload)
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat du vendeur invalide ou expire !")
        return

    print("[Acheteur] Certificat X.509 du vendeur verifie OK")

    # Génère 32 octets aléatoires = clé AES-256 de session
    aes_key = os.urandom(32)

    # Chiffre la clé AES avec la clé publique RSA extraite du certificat
    # → seul le vendeur (avec sa clé privée) peut la déchiffrer
    cle_pub_vendeur = cert.public_key()
    aes_key_chiffree = chiffrer_rsa(aes_key, cle_pub_vendeur)

    client.publish(
        f"shop/handshake/key/{BUYER_ID}",
        base64.b64encode(aes_key_chiffree)
    )
    print("[Acheteur] Cle AES-256 envoyee (chiffree RSA-2048)")


def _handle_catalogue(payload):
    # On reçoit le catalogue chiffré du vendeur.
    # On vérifie : 1) le certificat joint  2) le déchiffrement AES  3) la signature RSA
    global catalogue

    msg = json.loads(payload)

    # Vérifie le certificat inclus dans le message (même vérification qu'au handshake)
    cert = load_pem_x509_certificate(msg["cert"].encode())
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat invalide dans le catalogue !")
        return

    # Déchiffre le catalogue avec notre clé AES de session
    contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

    # Vérifie que la signature RSA correspond bien au contenu déchiffré
    # → prouve que le catalogue vient du vendeur et n'a pas été altéré
    hash_calcule = calculer_hash(contenu)
    signature = base64.b64decode(msg["hash"])
    if not verifier_signature(hash_calcule, signature, cert.public_key()):
        print("[Acheteur] ALERTE : integrite du catalogue compromise !")
        return

    catalogue = json.loads(contenu)
    print("[Acheteur] Catalogue recu, dechiffre et verifie (SHA-1 OK)")
    catalogue_pret.set()  # signale que le catalogue est prêt → le thread principal peut continuer


def _handle_confirmation(payload):
    # On reçoit la confirmation de commande chiffrée du vendeur.
    # Même processus de vérification que pour le catalogue.
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
    confirmation_prete.set()  # signale que la confirmation est arrivée → on peut quitter


def afficher_catalogue():
    # Affiche proprement les produits reçus dans le terminal
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
    client.loop_start()  # démarre la réception MQTT dans un thread séparé

    # Attend que le catalogue soit reçu et déchiffré (timeout 15 secondes)
    print("[Acheteur] En attente du catalogue...")
    if not catalogue_pret.wait(timeout=15):
        print("[Acheteur] Timeout — le vendeur ne repond pas (Mosquitto est-il lance ?)")
        client.loop_stop()
        return

    afficher_catalogue()

    # Demande à l'utilisateur de choisir un produit (validation de la saisie)
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

    # Chiffre la commande en AES-256 avec la clé de session
    commande_bytes = json.dumps(produit, ensure_ascii=False).encode()
    data_chiffre = chiffrer_aes(commande_bytes, aes_key)

    # Calcule le hash SHA-1 pour l'intégrité (sans signature RSA : l'acheteur n'a pas de clé privée)
    hash_msg = calculer_hash(commande_bytes)

    message = json.dumps({
        "data": base64.b64encode(data_chiffre).decode(),
        "hash": base64.b64encode(hash_msg).decode(),
    })
    client.publish(f"shop/commande/{BUYER_ID}", message)
    print("[Acheteur] Commande chiffree (AES-256) envoyee")

    # Attend la confirmation du vendeur (timeout 15 secondes)
    if not confirmation_prete.wait(timeout=15):
        print("[Acheteur] Timeout — pas de confirmation recue")

    client.loop_stop()
    client.disconnect()


if __name__ == "__main__":
    main()
