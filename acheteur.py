# =============================================================================
# acheteur.py — Le client de la boutique MQTT
# =============================================================================
# Ce fichier représente un acheteur qui se connecte à la boutique du vendeur
# via un broker MQTT (Mosquitto). Toute la communication est chiffrée
# "à la main" en Python, sans TLS réseau : RSA pour l'échange de clé,
# AES-256 pour les messages, SHA-1 pour l'intégrité, X.509 pour l'identité.
#
# Schéma global de ce que fait cet acheteur :
#   1. Se connecte au broker MQTT
#   2. Envoie une demande de handshake au vendeur
#   3. Reçoit et vérifie le certificat X.509 du vendeur
#   4. Génère une clé AES de session et la chiffre avec la clé publique RSA
#   5. Attend le catalogue chiffré, le déchiffre et l'affiche
#   6. L'utilisateur choisit un produit
#   7. La commande est chiffrée et envoyée au vendeur
#   8. La confirmation chiffrée du vendeur est reçue et affichée
# =============================================================================

import json       # pour sérialiser/désérialiser les messages échangés
import base64     # pour encoder les bytes en texte (MQTT transporte du texte)
import os         # pour générer des bytes aléatoires (clé AES, IV)
import uuid       # pour générer un identifiant unique à chaque acheteur
import threading  # pour synchroniser les étapes sans faire de polling actif
import paho.mqtt.client as mqtt  # bibliothèque MQTT pour Python

# On a besoin de charger le certificat X.509 pour vérifier l'identité du vendeur
from cryptography.x509 import load_pem_x509_certificate

# On importe toutes nos fonctions crypto depuis le module partagé
# (chiffrement AES, RSA, hash SHA-1, vérification de signature et de certificat)
from crypto_utils import (
    chiffrer_aes, dechiffrer_aes, chiffrer_rsa,
    calculer_hash, verifier_signature, verifier_certificat
)

# -------------------------------------------------------------------
# CONFIGURATION DU BROKER
# -------------------------------------------------------------------
# On suppose que Mosquitto tourne en local sur le port par défaut.
# Si le broker est sur une autre machine, changer BROKER en conséquence.
BROKER = "localhost"
PORT = 1883  # port MQTT standard (non chiffré)

# -------------------------------------------------------------------
# IDENTIFIANT UNIQUE DE CET ACHETEUR
# -------------------------------------------------------------------
# uuid4() génère un identifiant aléatoire globalement unique (128 bits).
# On prend seulement les 8 premiers caractères pour rester lisible dans les logs.
# Exemple de valeur : "a3f9b12c"
#
# L'intérêt : si on lance plusieurs instances d'acheteur en même temps,
# chacune a son propre identifiant et donc ses propres topics MQTT
# → elles ne se "mélangent" pas.
BUYER_ID = str(uuid.uuid4())[:8]

# -------------------------------------------------------------------
# ÉTAT GLOBAL DE LA SESSION
# -------------------------------------------------------------------

# La clé AES de session — générée pendant le handshake.
# Elle vaut None au démarrage, puis est remplie dans _handle_cert().
# Tout ce qui est échangé après le handshake est chiffré avec cette clé.
aes_key = None

# Le catalogue de produits reçu du vendeur.
# Rempli dans _handle_catalogue() après déchiffrement et vérification.
catalogue = []

# --- Événements de synchronisation entre threads ---
# MQTT tourne dans son propre thread (loop_start).
# On a besoin d'un mécanisme pour "bloquer" le thread principal
# jusqu'à ce que le catalogue soit arrivé ou que la confirmation soit reçue.
#
# threading.Event() fonctionne comme un drapeau :
#   .wait()  → bloque jusqu'à ce que le drapeau soit levé (ou timeout)
#   .set()   → lève le drapeau, débloque tous ceux qui attendent
#
# catalogue_pret    : levé quand le catalogue est déchiffré et prêt à afficher
# confirmation_prete : levé quand la confirmation de commande est reçue
catalogue_pret = threading.Event()
confirmation_prete = threading.Event()


# =============================================================================
# CRÉATION DU CLIENT MQTT
# =============================================================================

def _creer_client_mqtt(client_id: str):
    """
    Crée un client MQTT compatible avec paho-mqtt v1.x et v2.x.

    La version 2 de paho-mqtt a introduit une enum CallbackAPIVersion qui n'existe
    pas dans la v1. Pour éviter de planter selon la version installée, on essaie
    d'abord avec la nouvelle API et on retombe sur l'ancienne si besoin.
    """
    try:
        # paho-mqtt >= 2.0 : passage obligatoire de la version d'API
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        # paho-mqtt < 2.0 : l'attribut CallbackAPIVersion n'existe pas encore
        return mqtt.Client(client_id=client_id)


# On crée le client MQTT de cet acheteur avec un nom unique
# (utile pour les logs de Mosquitto et pour distinguer les connexions)
client = _creer_client_mqtt(f"acheteur_{BUYER_ID}")


# =============================================================================
# CALLBACKS MQTT
# =============================================================================

def on_connect(cl, userdata, flags, rc):
    """
    Appelé automatiquement par paho-mqtt dès qu'on est connecté au broker.

    C'est ici qu'on s'abonne aux topics et qu'on envoie la première requête
    au vendeur pour initier le handshake.
    """
    print(f"[Acheteur {BUYER_ID}] Connecte au broker MQTT")

    # On s'abonne uniquement aux topics qui incluent notre buyer_id.
    # Cela garantit qu'on ne reçoit que les messages qui nous sont destinés.
    # Un autre acheteur connecté en même temps ne verra pas nos messages et vice-versa.

    # Topic pour recevoir le certificat X.509 du vendeur (étape 1 du handshake)
    cl.subscribe(f"shop/handshake/cert/{BUYER_ID}")

    # Topic pour recevoir le catalogue chiffré en AES (après le handshake)
    cl.subscribe(f"shop/catalogue/{BUYER_ID}")

    # Topic pour recevoir la confirmation de commande chiffrée
    cl.subscribe(f"shop/confirmation/{BUYER_ID}")

    # Démarre le handshake : on publie notre identifiant sur le topic général
    # que le vendeur écoute en permanence
    cl.publish("shop/handshake/request", json.dumps({"buyer_id": BUYER_ID}))
    print("[Acheteur] Demande de connexion envoyee au vendeur...")


def on_message(cl, userdata, msg):
    """
    Appelé automatiquement à chaque message MQTT reçu sur un topic abonné.

    Ce callback fait office d'aiguillage : il lit le nom du topic
    et appelle la bonne fonction de traitement.
    On entoure tout d'un try/except pour ne pas planter silencieusement
    en cas de message malformé ou d'erreur crypto.
    """
    topic = msg.topic  # nom du topic MQTT sur lequel le message est arrivé

    try:
        # Message 1 : le vendeur nous envoie son certificat X.509
        if topic == f"shop/handshake/cert/{BUYER_ID}":
            _handle_cert(msg.payload)

        # Message 2 : le vendeur nous envoie le catalogue chiffré en AES
        elif topic == f"shop/catalogue/{BUYER_ID}":
            _handle_catalogue(msg.payload)

        # Message 3 : le vendeur confirme (ou rejette) notre commande
        elif topic == f"shop/confirmation/{BUYER_ID}":
            _handle_confirmation(msg.payload)

    except Exception as e:
        # On affiche l'erreur mais on ne fait pas planter le thread MQTT
        # pour que les autres messages puissent encore être traités
        print(f"[Acheteur] Erreur traitement message: {e}")


# =============================================================================
# TRAITEMENT DES MESSAGES REÇUS
# =============================================================================

def _handle_cert(payload):
    """
    Traitement du certificat X.509 envoyé par le vendeur.

    Étapes :
      1. Charger et vérifier le certificat (validité, signature)
      2. Générer une clé AES-256 aléatoire (clé de session)
      3. Chiffrer la clé AES avec la clé publique RSA du vendeur
      4. Publier la clé AES chiffrée sur le topic dédié

    Après ça, le vendeur et nous partageons la même clé AES secrète
    et toute la communication se fait en AES.
    """
    global aes_key  # on va écrire dans la variable globale de session

    # Le payload est directement les octets PEM du certificat X.509
    # (pas de JSON ici, le vendeur envoie le fichier .pem brut)
    cert = load_pem_x509_certificate(payload)

    # Vérification du certificat :
    #   - est-il encore dans sa fenêtre de validité ?
    #   - sa signature est-elle correcte (autosigné dans notre cas) ?
    # Si le certificat est invalide, on abandonne immédiatement — inutile de continuer.
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat du vendeur invalide ou expire !")
        return

    print("[Acheteur] Certificat X.509 du vendeur verifie OK")

    # os.urandom(32) génère 32 octets vraiment aléatoires depuis le système d'exploitation.
    # 32 octets = 256 bits → c'est la clé AES-256 qu'on utilisera pour toute la session.
    # Cette clé n'existe que dans notre mémoire (pas sauvegardée sur disque).
    aes_key = os.urandom(32)

    # On extrait la clé publique RSA qui est embarquée dans le certificat.
    # Cette clé publique est connue de tout le monde — c'est son rôle.
    cle_pub_vendeur = cert.public_key()

    # On chiffre notre clé AES avec la clé publique RSA du vendeur.
    # Seul le vendeur (qui possède la clé PRIVÉE correspondante) pourra déchiffrer.
    # C'est le principe fondamental du chiffrement asymétrique.
    aes_key_chiffree = chiffrer_rsa(aes_key, cle_pub_vendeur)

    # On publie la clé AES chiffrée en base64 sur le topic dédié.
    # (base64 parce que MQTT peut mal gérer les bytes bruts dans certaines configs)
    client.publish(
        f"shop/handshake/key/{BUYER_ID}",
        base64.b64encode(aes_key_chiffree)
    )
    print("[Acheteur] Cle AES-256 envoyee (chiffree RSA-2048)")


def _handle_catalogue(payload):
    """
    Traitement du catalogue chiffré reçu du vendeur.

    Le message arrive sous forme de JSON contenant :
      - "data" : le catalogue sérialisé en JSON, chiffré en AES-256, encodé base64
      - "hash" : le hash SHA-1 du catalogue original, signé RSA, encodé base64
      - "cert" : le certificat PEM du vendeur (pour vérifier la signature)

    Étapes de vérification :
      1. Vérifier le certificat joint au message
      2. Déchiffrer "data" avec notre clé AES de session
      3. Recalculer le hash SHA-1 sur les données déchiffrées
      4. Vérifier la signature RSA sur ce hash
      5. Si tout est OK, charger le catalogue et signaler qu'il est prêt
    """
    global catalogue  # on va remplir la liste globale des produits

    # Le payload est un JSON encodé en bytes → on le parse en dictionnaire Python
    msg = json.loads(payload)

    # Le vendeur joint son certificat dans chaque message signé.
    # On re-vérifie à chaque fois (bonne pratique, même si on l'a déjà vérifié
    # pendant le handshake — un message pourrait avoir été intercepté et rejoué).
    cert = load_pem_x509_certificate(msg["cert"].encode())
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat invalide dans le catalogue !")
        return

    # Déchiffrement AES-256 :
    #   - base64.b64decode() reconvertit la chaîne texte en bytes bruts
    #   - dechiffrer_aes() extrait l'IV (16 premiers octets) puis déchiffre
    # Résultat : les bytes du catalogue JSON en clair
    contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

    # Vérification de l'intégrité et de l'authenticité :
    #   1. On recalcule le hash SHA-1 sur le contenu déchiffré
    #   2. On compare ce hash à la signature RSA envoyée par le vendeur
    #
    # Si ça correspond → le catalogue vient VRAIMENT du vendeur et n'a pas été modifié.
    # Si ça ne correspond pas → quelqu'un a trafiqué le message en transit (attaque MITM).
    hash_calcule = calculer_hash(contenu)
    signature = base64.b64decode(msg["hash"])
    if not verifier_signature(hash_calcule, signature, cert.public_key()):
        print("[Acheteur] ALERTE : integrite du catalogue compromise !")
        return

    # Tout est OK : on désérialise le JSON en liste Python de dictionnaires produits
    catalogue = json.loads(contenu)

    print("[Acheteur] Catalogue recu, dechiffre et verifie (SHA-1 OK)")

    # On lève l'événement pour débloquer le thread principal qui attend dans main()
    # (il fait un .wait() bloquant depuis le début)
    catalogue_pret.set()


def _handle_confirmation(payload):
    """
    Traitement de la confirmation de commande chiffrée envoyée par le vendeur.

    Même logique de vérification que pour le catalogue :
    certificat → déchiffrement AES → vérification signature RSA.

    Si tout est valide, on affiche la confirmation à l'utilisateur
    et on signale que le programme peut se terminer proprement.
    """
    # Parse du JSON reçu
    msg = json.loads(payload)

    # Vérification du certificat joint à la confirmation
    cert = load_pem_x509_certificate(msg["cert"].encode())
    if not verifier_certificat(cert):
        print("[Acheteur] ALERTE : certificat invalide dans la confirmation !")
        return

    # Déchiffrement AES de la confirmation avec notre clé de session
    contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

    # Vérification de la signature RSA du vendeur sur le hash de la confirmation
    # → garantit que c'est bien le vendeur qui a généré cette réponse
    hash_calcule = calculer_hash(contenu)
    signature = base64.b64decode(msg["hash"])
    if not verifier_signature(hash_calcule, signature, cert.public_key()):
        print("[Acheteur] ALERTE : integrite de la confirmation compromise !")
        return

    # Désérialisation de la confirmation (statut, message humain, numéro de référence)
    confirmation = json.loads(contenu)

    # Affichage propre de la confirmation dans le terminal
    print(f"\n{'='*45}")
    print(f"         CONFIRMATION DE COMMANDE")
    print(f"{'='*45}")
    print(f"  Statut    : {confirmation['statut']}")
    print(f"  Message   : {confirmation['message']}")
    print(f"  Reference : {confirmation['reference']}")
    print(f"{'='*45}\n")

    # Lève l'événement → débloque le .wait() dans main() et permet la déconnexion propre
    confirmation_prete.set()


# =============================================================================
# AFFICHAGE
# =============================================================================

def afficher_catalogue():
    """
    Affiche le catalogue de produits dans le terminal, joliment formaté.

    On utilise des f-strings avec des formats de largeur fixe (:<22 et :>4)
    pour aligner les colonnes et que ça soit lisible même avec des noms longs.
    """
    print(f"\n{'='*45}")
    print(f"         CATALOGUE — BOUTIQUE MQTT")
    print(f"{'='*45}")

    # Pour chaque produit du catalogue, on affiche : [numéro]  nom   prix
    # L'alignement est géré par les spécificateurs de format Python
    for item in catalogue:
        print(f"  [{item['id']:2d}]  {item['nom']:<22} {item['prix']:>4} EUR")

    print(f"{'='*45}")


# =============================================================================
# PROGRAMME PRINCIPAL
# =============================================================================

def main():
    """
    Point d'entrée de l'acheteur.

    On configure les callbacks MQTT, on se connecte au broker,
    puis on orchestre le déroulement grâce aux événements de synchronisation.
    """
    # Branchement des fonctions de rappel sur le client MQTT
    client.on_connect = on_connect  # appelé à la connexion au broker
    client.on_message = on_message  # appelé à chaque message reçu

    # Connexion au broker Mosquitto (doit être lancé avant d'arriver ici)
    client.connect(BROKER, PORT)

    # loop_start() démarre la boucle de réception MQTT dans un thread SÉPARÉ.
    # Ça permet à notre thread principal de continuer à tourner pendant ce temps
    # (afficher le catalogue, lire l'input de l'utilisateur, etc.)
    client.loop_start()

    # --- Attente du catalogue ---
    # On bloque ici jusqu'à ce que _handle_catalogue() appelle catalogue_pret.set().
    # Le timeout de 15 secondes évite de rester bloqué indéfiniment si le vendeur
    # ne répond pas (Mosquitto pas lancé, vendeur planté, etc.)
    print("[Acheteur] En attente du catalogue...")
    if not catalogue_pret.wait(timeout=15):
        # wait() retourne False si le timeout s'est écoulé sans que .set() soit appelé
        print("[Acheteur] Timeout — le vendeur ne repond pas (Mosquitto est-il lance ?)")
        client.loop_stop()
        return  # on quitte proprement plutôt que de rester bloqué

    # Le catalogue est arrivé et vérifié : on l'affiche à l'utilisateur
    afficher_catalogue()

    # --- Saisie du choix de l'utilisateur ---
    # Boucle tant que l'utilisateur ne saisit pas un numéro valide (entre 1 et 10).
    # On gère aussi le cas où l'utilisateur tape du texte (ValueError sur int()).
    while True:
        try:
            choix = int(input("\nChoisissez un produit (1-10) : "))
            if 1 <= choix <= 10:
                break  # saisie valide, on sort de la boucle
            print("  Entrez un numero entre 1 et 10.")
        except ValueError:
            # int() a échoué parce que l'utilisateur a tapé un truc qui n'est pas un entier
            print("  Entrez un nombre valide.")

    # Récupère le dictionnaire produit correspondant au numéro choisi
    # next() avec un générateur retourne le premier élément qui matche la condition
    produit = next(p for p in catalogue if p["id"] == choix)
    print(f"\n[Acheteur] Envoi de la commande : {produit['nom']} a {produit['prix']} EUR")

    # --- Chiffrement et envoi de la commande ---

    # Sérialise le produit choisi en JSON puis en bytes
    # (ensure_ascii=False pour garder les accents dans les noms de produits)
    commande_bytes = json.dumps(produit, ensure_ascii=False).encode()

    # Chiffre la commande en AES-256 avec notre clé de session
    # → même le broker Mosquitto ne peut pas lire le contenu du message
    data_chiffre = chiffrer_aes(commande_bytes, aes_key)

    # Calcule le hash SHA-1 pour permettre au vendeur de vérifier l'intégrité.
    # Note : on envoie le hash BRUT sans signature RSA car l'acheteur n'a pas de clé privée.
    # (Dans une vraie appli, l'acheteur aurait aussi sa propre paire de clés RSA)
    hash_msg = calculer_hash(commande_bytes)

    # Assemble le message final en JSON (même format que les messages du vendeur)
    message = json.dumps({
        "data": base64.b64encode(data_chiffre).decode(),   # commande chiffrée AES → base64 → str
        "hash": base64.b64encode(hash_msg).decode(),       # hash SHA-1 brut → base64 → str
        # pas de "cert" ici car l'acheteur n'a pas de certificat dans cette simulation
    })

    # Publication sur le topic de commande spécifique à cet acheteur
    client.publish(f"shop/commande/{BUYER_ID}", message)
    print("[Acheteur] Commande chiffree (AES-256) envoyee")

    # --- Attente de la confirmation ---
    # Même principe que pour le catalogue : on bloque 15 secondes maximum.
    if not confirmation_prete.wait(timeout=15):
        print("[Acheteur] Timeout — pas de confirmation recue")

    # Déconnexion propre : on arrête le thread MQTT et on ferme la connexion
    client.loop_stop()
    client.disconnect()


# Point d'entrée standard Python
# (empêche main() d'être appelé si ce fichier est importé par un autre module)
if __name__ == "__main__":
    main()
