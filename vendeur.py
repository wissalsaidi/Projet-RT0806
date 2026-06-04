# =============================================================================
# vendeur.py — Le serveur / vendeur de la boutique MQTT
# =============================================================================
# Ce fichier représente le côté "serveur" de notre boutique MQTT sécurisée.
# Le vendeur :
#   - écoute en permanence les demandes de connexion des acheteurs
#   - réalise un handshake sécurisé avec chacun (échange de clé RSA + AES)
#   - envoie le catalogue chiffré en AES + signé en RSA
#   - reçoit et traite les commandes chiffrées
#   - renvoie une confirmation chiffrée + signée
#
# Le vendeur peut gérer PLUSIEURS acheteurs en même temps grâce au BUYER_ID
# présent dans chaque topic MQTT. Chaque acheteur a sa propre clé AES de session.
# =============================================================================

import json    # pour sérialiser/désérialiser les messages JSON échangés
import base64  # pour convertir des bytes en texte transmissible via MQTT
import paho.mqtt.client as mqtt  # bibliothèque Python pour le protocole MQTT

# Pour charger la clé privée RSA depuis le fichier PEM sur disque
from cryptography.hazmat.primitives import serialization

# Nos fonctions crypto maison : AES, RSA, SHA-1
from crypto_utils import (
    chiffrer_aes, dechiffrer_aes, dechiffrer_rsa,
    calculer_hash, signer
)

# -------------------------------------------------------------------
# CONFIGURATION DU BROKER
# -------------------------------------------------------------------
# Le vendeur se connecte lui aussi à Mosquitto, comme n'importe quel client MQTT.
# (Dans MQTT, tout le monde est client — il n'y a pas de connexion directe entre clients)
BROKER = "localhost"
PORT = 1883  # port MQTT standard non chiffré

# -------------------------------------------------------------------
# CATALOGUE DES PRODUITS
# -------------------------------------------------------------------
# Liste des produits proposés par la boutique.
# Ce catalogue sera sérialisé en JSON, chiffré en AES-256 et signé en RSA
# avant d'être envoyé à chaque acheteur.
CATALOGUE = [
    {"id": 1,  "nom": "Clavier",        "prix": 49},
    {"id": 2,  "nom": "Souris",          "prix": 29},
    {"id": 3,  "nom": "Ecran 27 pouces", "prix": 299},
    {"id": 4,  "nom": "Casque audio",    "prix": 79},
    {"id": 5,  "nom": "Webcam HD",       "prix": 59},
    {"id": 6,  "nom": "Cle USB 64Go",   "prix": 12},
    {"id": 7,  "nom": "Cable HDMI",     "prix": 15},
    {"id": 8,  "nom": "Tapis souris",    "prix": 19},
    {"id": 9,  "nom": "Hub USB",         "prix": 35},
    {"id": 10, "nom": "Support PC",      "prix": 45},
]


# =============================================================================
# COMPATIBILITÉ PAHO-MQTT
# =============================================================================

def _creer_client_mqtt(client_id: str):
    """
    Crée un client MQTT compatible paho v1.x et v2.x.

    paho-mqtt 2.0 a introduit l'enum CallbackAPIVersion (breaking change).
    Cette fonction masque cette différence de version pour que le code
    fonctionne peu importe la version installée sur la machine.
    """
    try:
        # Syntaxe pour paho-mqtt >= 2.0
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        # Syntaxe pour paho-mqtt < 2.0 (VERSION1 n'existe pas encore)
        return mqtt.Client(client_id=client_id)


# =============================================================================
# CLASSE VENDEUR
# =============================================================================

class Vendeur:
    """
    Classe principale du vendeur.

    Elle regroupe toute la logique : gestion des sessions, handshake,
    envoi du catalogue et traitement des commandes.
    Utiliser une classe permet de stocker proprement l'état partagé
    (clé privée, certificat, sessions AES) sans variables globales.
    """

    def __init__(self):
        """
        Initialisation du vendeur : chargement des clés et du certificat,
        création du client MQTT et branchement des callbacks.
        """

        # --- Chargement de la clé privée RSA ---
        # La clé privée est sensible : elle ne doit JAMAIS être partagée.
        # Elle est utilisée pour deux choses :
        #   1. Déchiffrer la clé AES envoyée par l'acheteur
        #   2. Signer les messages envoyés (catalogue, confirmation)
        #
        # password=None car notre fichier PEM n'est pas protégé par mot de passe
        # (dans un vrai système en production, il devrait l'être)
        with open("keys/vendeur_private.pem", "rb") as f:
            self.cle_privee = serialization.load_pem_private_key(f.read(), password=None)

        # --- Chargement du certificat X.509 ---
        # Le certificat est la "carte d'identité" du vendeur.
        # Il contient la clé publique + des infos d'identité, le tout signé.
        # On le charge en mémoire une bonne fois pour l'envoyer à chaque acheteur
        # qui en fait la demande pendant le handshake.
        with open("keys/vendeur_cert.pem", "rb") as f:
            self.cert_pem = f.read()  # bytes bruts du fichier PEM

        # --- Dictionnaire des sessions actives ---
        # Associe chaque acheteur à sa clé AES de session unique.
        # Format : { "buyer_id_abc12345": b"\x3f\xa1\x00..." }
        #
        # Pourquoi un dictionnaire et pas une variable unique ?
        # Parce que plusieurs acheteurs peuvent être connectés EN MÊME TEMPS.
        # Chacun a sa propre clé AES négociée pendant son handshake.
        # Sans ce dictionnaire, un acheteur B pourrait utiliser la clé d'un acheteur A.
        self.sessions = {}

        # --- Création du client MQTT ---
        # Le vendeur s'identifie simplement comme "vendeur" auprès du broker.
        self.client = _creer_client_mqtt("vendeur")

        # Branchement des callbacks : paho-mqtt appellera ces méthodes
        # automatiquement lors des événements réseau
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    # =========================================================================
    # CALLBACKS MQTT
    # =========================================================================

    def _on_connect(self, client, userdata, flags, rc):
        """
        Appelé automatiquement par paho-mqtt une fois connecté au broker.

        rc=0 signifie succès. rc != 0 indique une erreur de connexion
        (mauvais mot de passe, IP refusée, etc.) mais on ne gère pas ici
        pour rester simple.
        """
        print(f"[Vendeur] Connecte au broker MQTT (code={rc})")

        # On s'abonne aux trois types de messages entrants :

        # 1. Demandes initiales de connexion des acheteurs
        #    (topic sans buyer_id car à ce stade on ne les connaît pas encore)
        client.subscribe("shop/handshake/request")

        # 2. Clés AES envoyées par les acheteurs après vérification du certificat
        #    Le "+" est un wildcard MQTT qui accepte n'importe quel buyer_id
        #    → on reçoit les clés de TOUS les acheteurs sur ce topic
        client.subscribe("shop/handshake/key/+")

        # 3. Commandes passées par les acheteurs (également avec wildcard)
        client.subscribe("shop/commande/+")

        print("[Vendeur] En attente d'acheteurs...\n")

    def _on_message(self, client, userdata, msg):
        """
        Aiguillage des messages MQTT reçus vers la bonne méthode de traitement.

        On lit le nom du topic pour savoir quel type de message c'est,
        puis on extrait le buyer_id quand il est présent dans le topic.
        """
        topic = msg.topic

        try:
            if topic == "shop/handshake/request":
                # Nouveau acheteur qui veut se connecter
                self._handle_request(msg.payload)

            elif topic.startswith("shop/handshake/key/"):
                # Un acheteur nous envoie sa clé AES chiffrée.
                # On extrait le buyer_id depuis la fin du topic (après le dernier "/")
                buyer_id = topic.split("/")[-1]
                self._handle_key(buyer_id, msg.payload)

            elif topic.startswith("shop/commande/"):
                # Un acheteur passe une commande.
                # Même extraction du buyer_id depuis le topic.
                buyer_id = topic.split("/")[-1]
                self._handle_commande(buyer_id, msg.payload)

        except Exception as e:
            # On log l'erreur sans faire planter le vendeur.
            # Important : un bug sur la commande d'un acheteur ne doit pas
            # affecter les autres acheteurs connectés en même temps.
            print(f"[Vendeur] Erreur traitement message sur '{topic}': {e}")

    # =========================================================================
    # TRAITEMENT DES MESSAGES
    # =========================================================================

    def _handle_request(self, payload):
        """
        Traitement d'une demande de connexion d'un nouvel acheteur.

        Un acheteur vient d'arriver et annonce son identifiant.
        Notre réponse : lui envoyer notre certificat X.509 pour qu'il puisse :
          - vérifier notre identité (est-ce vraiment le vendeur ?)
          - extraire notre clé publique RSA (pour chiffrer la clé AES)
        """
        # Parse du JSON contenant le buyer_id de l'acheteur
        data = json.loads(payload)
        buyer_id = data["buyer_id"]

        print(f"[Vendeur] Demande de connexion de l'acheteur '{buyer_id}'")

        # On publie le certificat X.509 brut (bytes PEM) sur le topic spécifique
        # à cet acheteur. Seul lui est abonné à ce topic → les autres n'y ont pas accès.
        self.client.publish(f"shop/handshake/cert/{buyer_id}", self.cert_pem)

        print(f"[Vendeur] Certificat X.509 envoye a '{buyer_id}'")

    def _handle_key(self, buyer_id, payload):
        """
        Réception de la clé AES chiffrée envoyée par un acheteur.

        L'acheteur a :
          1. Généré une clé AES-256 aléatoire
          2. Chiffré cette clé avec notre clé publique RSA
          3. Publié le résultat ici

        On fait l'inverse : on déchiffre avec notre clé PRIVÉE RSA.
        Résultat : on a la même clé AES que l'acheteur → session sécurisée établie.
        """
        # Décode base64 → bytes bruts (les bytes chiffrés RSA de la clé AES)
        aes_key_chiffree = base64.b64decode(payload)

        # Déchiffrement RSA avec notre clé privée
        # → on récupère les 32 bytes de la clé AES que l'acheteur a générée
        aes_key = dechiffrer_rsa(aes_key_chiffree, self.cle_privee)

        # On mémorise la clé AES associée à ce buyer_id dans notre dictionnaire de sessions.
        # À partir de là, tous les messages avec cet acheteur seront chiffrés avec cette clé.
        self.sessions[buyer_id] = aes_key

        print(f"[Vendeur] Cle AES-256 dechiffree pour '{buyer_id}' — session etablie")

        # Le handshake est terminé : on peut maintenant envoyer le catalogue
        self._envoyer_catalogue(buyer_id)

    def _envoyer_catalogue(self, buyer_id):
        """
        Envoi du catalogue chiffré et signé à un acheteur spécifique.

        Le catalogue est protégé de deux façons :
          - Confidentialité : chiffré en AES-256 avec la clé de session
            → personne d'autre ne peut lire le catalogue (même pas le broker)
          - Authenticité + Intégrité : hash SHA-1 signé RSA
            → l'acheteur peut vérifier que c'est bien nous qui avons envoyé ça
            → et que le contenu n'a pas été modifié pendant le transit
        """
        # Récupère la clé AES de session de cet acheteur
        aes_key = self.sessions[buyer_id]

        # Sérialise le catalogue Python en JSON puis en bytes
        catalogue_bytes = json.dumps(CATALOGUE, ensure_ascii=False).encode()

        # --- Chiffrement AES-256 ---
        # Un IV aléatoire est généré et préfixé automatiquement par chiffrer_aes()
        # → chaque envoi du catalogue produit un résultat différent même si le contenu est identique
        data_chiffre = chiffrer_aes(catalogue_bytes, aes_key)

        # --- Signature RSA ---
        # 1. On calcule l'empreinte SHA-1 du catalogue (20 bytes)
        # 2. On signe cette empreinte avec notre clé PRIVÉE RSA
        #    → n'importe qui avec notre clé PUBLIQUE peut vérifier qu'on l'a signé
        hash_msg = calculer_hash(catalogue_bytes)
        signature = signer(hash_msg, self.cle_privee)

        # --- Assemblage du message JSON ---
        # Le "cert" est inclus pour que l'acheteur puisse vérifier la signature
        # sans avoir à stocker notre certificat de son côté
        message = json.dumps({
            "data": base64.b64encode(data_chiffre).decode(),  # catalogue chiffré AES → base64 → str
            "hash": base64.b64encode(signature).decode(),     # signature RSA → base64 → str
            "cert": self.cert_pem.decode()                    # notre certificat PEM en texte
        })

        self.client.publish(f"shop/catalogue/{buyer_id}", message)
        print(f"[Vendeur] Catalogue chiffre (AES-256) envoye a '{buyer_id}'")

    def _handle_commande(self, buyer_id, payload):
        """
        Traitement d'une commande chiffrée envoyée par un acheteur.

        L'acheteur envoie :
          - "data" : le produit commandé en JSON, chiffré en AES
          - "hash" : le hash SHA-1 brut du message (sans signature RSA car l'acheteur n'a pas de clé privée)

        On vérifie l'intégrité, on déchiffre, puis on confirme la commande.
        """

        # Sécurité : on vérifie qu'on a bien une session ouverte avec cet acheteur.
        # Si quelqu'un publie directement sur shop/commande/toto sans avoir fait le handshake,
        # on ignore le message (on ne connaît pas sa clé AES de toute façon).
        if buyer_id not in self.sessions:
            print(f"[Vendeur] Session inconnue pour '{buyer_id}' — commande ignoree")
            return

        # Récupère la clé AES de session de cet acheteur
        aes_key = self.sessions[buyer_id]

        # Parse du JSON reçu
        msg = json.loads(payload)

        # --- Déchiffrement AES ---
        # On récupère le JSON de la commande en clair
        contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

        # --- Vérification de l'intégrité ---
        # L'acheteur n'a pas de clé privée RSA dans cette simulation,
        # donc il ne peut pas signer ses messages.
        # Il envoie le hash SHA-1 brut et on le compare au hash qu'on calcule nous-mêmes.
        # Si les deux correspondent → le message n'a pas été altéré en transit.
        # (Sans signature RSA, on ne peut pas prouver QUI a envoyé, mais on peut vérifier l'intégrité)
        hash_recu = base64.b64decode(msg["hash"])
        hash_calcule = calculer_hash(contenu)
        if hash_recu != hash_calcule:
            # Les hashes ne correspondent pas → le message a été modifié
            print(f"[Vendeur] ALERTE : integrite compromise pour '{buyer_id}'")
            return

        # Désérialise la commande JSON en dictionnaire Python
        commande = json.loads(contenu)

        print(f"\n[Vendeur] >>> Commande de '{buyer_id}' : {commande['nom']} a {commande['prix']}EUR")

        # Envoie la confirmation de commande à l'acheteur
        self._envoyer_confirmation(buyer_id, commande)

    def _envoyer_confirmation(self, buyer_id, commande):
        """
        Envoi d'une confirmation de commande chiffrée et signée à l'acheteur.

        Même logique de protection que pour le catalogue :
        AES pour la confidentialité, RSA pour l'authenticité et l'intégrité.
        """
        # Récupère la clé de session de cet acheteur
        aes_key = self.sessions[buyer_id]

        # --- Construction de la réponse de confirmation ---
        # On génère une référence de commande basée sur le buyer_id
        # (les 8 premiers caractères en majuscules, préfixés de "CMD-")
        confirmation = {
            "statut": "OK",
            "message": f"Commande confirmee : {commande['nom']} a {commande['prix']}EUR",
            "reference": f"CMD-{buyer_id[:8].upper()}"
        }

        # Sérialise la confirmation en bytes pour le chiffrement
        conf_bytes = json.dumps(confirmation, ensure_ascii=False).encode()

        # --- Chiffrement AES + Signature RSA ---
        # Exactement le même processus que pour le catalogue :
        # on chiffre pour la confidentialité et on signe pour l'authenticité
        data_chiffre = chiffrer_aes(conf_bytes, aes_key)
        hash_msg = calculer_hash(conf_bytes)
        signature = signer(hash_msg, self.cle_privee)

        # --- Assemblage et publication du message ---
        message = json.dumps({
            "data": base64.b64encode(data_chiffre).decode(),  # confirmation chiffrée
            "hash": base64.b64encode(signature).decode(),     # signature RSA du hash
            "cert": self.cert_pem.decode()                    # certificat pour vérifier la signature
        })

        self.client.publish(f"shop/confirmation/{buyer_id}", message)
        print(f"[Vendeur] Confirmation chiffree (AES-256) envoyee a '{buyer_id}'")

    # =========================================================================
    # DÉMARRAGE
    # =========================================================================

    def run(self):
        """
        Démarre le vendeur : connexion au broker MQTT et boucle d'écoute infinie.

        loop_forever() est une boucle bloquante qui gère automatiquement :
          - la réception et l'envoi de messages
          - les reconnexions en cas de déconnexion réseau
          - le maintien en vie de la connexion (keep-alive MQTT)
        Elle ne se termine que si on appelle client.disconnect() depuis un autre thread
        ou avec Ctrl+C.
        """
        self.client.connect(BROKER, PORT)

        # Bloque ici indéfiniment — le vendeur tourne tant qu'on ne le coupe pas
        self.client.loop_forever()


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":
    # Instancie et démarre le vendeur
    # (si ce fichier est importé dans un test, on n'exécute pas automatiquement)
    vendeur = Vendeur()
    vendeur.run()
