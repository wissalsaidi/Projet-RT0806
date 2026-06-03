import json
import base64
import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization
from crypto_utils import (
    chiffrer_aes, dechiffrer_aes, dechiffrer_rsa,
    calculer_hash, signer
)

BROKER = "localhost"
PORT = 1883

# Liste des produits vendus (envoyée chiffrée à chaque acheteur)
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


def _creer_client_mqtt(client_id: str):
    # Compatibilité entre paho-mqtt version 1.x et 2.x
    # (l'API a changé entre les deux versions)
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


class Vendeur:
    def __init__(self):
        # Charge la clé privée RSA depuis le fichier (nécessaire pour déchiffrer et signer)
        with open("keys/vendeur_private.pem", "rb") as f:
            self.cle_privee = serialization.load_pem_private_key(f.read(), password=None)

        # Charge le certificat X.509 en mémoire (sera envoyé brut aux acheteurs)
        with open("keys/vendeur_cert.pem", "rb") as f:
            self.cert_pem = f.read()

        # Dictionnaire qui associe chaque acheteur à sa clé AES de session
        # Format : { "buyer_id_abc12345": b"\x3f\xa1..." }
        # Permet de gérer plusieurs acheteurs connectés en même temps
        self.sessions = {}

        # Création du client MQTT et branchement des callbacks
        self.client = _creer_client_mqtt("vendeur")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc):
        print(f"[Vendeur] Connecte au broker MQTT (code={rc})")
        # S'abonne aux topics d'entrée :
        #   - shop/handshake/request : demandes de connexion de nouveaux acheteurs
        #   - shop/handshake/key/+   : clés AES envoyées par les acheteurs (+ = n'importe quel buyer_id)
        #   - shop/commande/+        : commandes passées par les acheteurs
        client.subscribe("shop/handshake/request")
        client.subscribe("shop/handshake/key/+")
        client.subscribe("shop/commande/+")
        print("[Vendeur] En attente d'acheteurs...\n")

    def _on_message(self, client, userdata, msg):
        # Routage des messages reçus vers la bonne méthode selon le topic
        topic = msg.topic
        try:
            if topic == "shop/handshake/request":
                self._handle_request(msg.payload)
            elif topic.startswith("shop/handshake/key/"):
                buyer_id = topic.split("/")[-1]  # extrait l'id depuis le topic
                self._handle_key(buyer_id, msg.payload)
            elif topic.startswith("shop/commande/"):
                buyer_id = topic.split("/")[-1]
                self._handle_commande(buyer_id, msg.payload)
        except Exception as e:
            print(f"[Vendeur] Erreur traitement message sur '{topic}': {e}")

    def _handle_request(self, payload):
        # Un acheteur demande à se connecter : on lui envoie notre certificat X.509
        # afin qu'il puisse vérifier notre identité et extraire notre clé publique RSA
        data = json.loads(payload)
        buyer_id = data["buyer_id"]
        print(f"[Vendeur] Demande de connexion de l'acheteur '{buyer_id}'")
        self.client.publish(f"shop/handshake/cert/{buyer_id}", self.cert_pem)
        print(f"[Vendeur] Certificat X.509 envoye a '{buyer_id}'")

    def _handle_key(self, buyer_id, payload):
        # L'acheteur nous envoie la clé AES chiffrée avec notre clé publique RSA.
        # On la déchiffre avec notre clé privée → on obtient la clé AES de session.
        # À partir de là, toute la communication avec cet acheteur sera chiffrée en AES.
        aes_key_chiffree = base64.b64decode(payload)
        aes_key = dechiffrer_rsa(aes_key_chiffree, self.cle_privee)
        self.sessions[buyer_id] = aes_key  # on mémorise la clé AES pour cet acheteur
        print(f"[Vendeur] Cle AES-256 dechiffree pour '{buyer_id}' — session etablie")
        self._envoyer_catalogue(buyer_id)

    def _envoyer_catalogue(self, buyer_id):
        # Récupère la clé AES de session de cet acheteur
        aes_key = self.sessions[buyer_id]
        catalogue_bytes = json.dumps(CATALOGUE, ensure_ascii=False).encode()

        # Chiffre le catalogue en AES-256 pour que seul cet acheteur puisse le lire
        data_chiffre = chiffrer_aes(catalogue_bytes, aes_key)

        # Calcule un hash SHA-1 du catalogue puis le signe avec la clé privée RSA
        # → l'acheteur pourra vérifier que le catalogue vient bien du vendeur et n'a pas été modifié
        hash_msg = calculer_hash(catalogue_bytes)
        signature = signer(hash_msg, self.cle_privee)

        # Emballe tout dans un JSON : données chiffrées + signature + certificat
        message = json.dumps({
            "data": base64.b64encode(data_chiffre).decode(),
            "hash": base64.b64encode(signature).decode(),
            "cert": self.cert_pem.decode()
        })
        self.client.publish(f"shop/catalogue/{buyer_id}", message)
        print(f"[Vendeur] Catalogue chiffre (AES-256) envoye a '{buyer_id}'")

    def _handle_commande(self, buyer_id, payload):
        # Vérifie que cet acheteur a bien une session ouverte
        if buyer_id not in self.sessions:
            print(f"[Vendeur] Session inconnue pour '{buyer_id}' — commande ignoree")
            return

        aes_key = self.sessions[buyer_id]
        msg = json.loads(payload)

        # Déchiffre la commande avec la clé AES de session
        contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

        # Vérifie l'intégrité : recalcule le hash SHA-1 et le compare à celui reçu
        # (l'acheteur n'a pas de clé privée, donc il envoie le hash brut sans signature RSA)
        hash_recu = base64.b64decode(msg["hash"])
        hash_calcule = calculer_hash(contenu)
        if hash_recu != hash_calcule:
            print(f"[Vendeur] ALERTE : integrite compromise pour '{buyer_id}'")
            return

        commande = json.loads(contenu)
        print(f"\n[Vendeur] >>> Commande de '{buyer_id}' : {commande['nom']} a {commande['prix']}EUR")
        self._envoyer_confirmation(buyer_id, commande)

    def _envoyer_confirmation(self, buyer_id, commande):
        aes_key = self.sessions[buyer_id]

        # Prépare la réponse de confirmation
        confirmation = {
            "statut": "OK",
            "message": f"Commande confirmee : {commande['nom']} a {commande['prix']}EUR",
            "reference": f"CMD-{buyer_id[:8].upper()}"
        }
        conf_bytes = json.dumps(confirmation, ensure_ascii=False).encode()

        # Chiffre la confirmation en AES + signe avec RSA (même principe que le catalogue)
        data_chiffre = chiffrer_aes(conf_bytes, aes_key)
        hash_msg = calculer_hash(conf_bytes)
        signature = signer(hash_msg, self.cle_privee)

        message = json.dumps({
            "data": base64.b64encode(data_chiffre).decode(),
            "hash": base64.b64encode(signature).decode(),
            "cert": self.cert_pem.decode()
        })
        self.client.publish(f"shop/confirmation/{buyer_id}", message)
        print(f"[Vendeur] Confirmation chiffree (AES-256) envoyee a '{buyer_id}'")

    def run(self):
        # Connexion au broker Mosquitto et démarrage de la boucle d'écoute (infinie)
        self.client.connect(BROKER, PORT)
        self.client.loop_forever()


if __name__ == "__main__":
    vendeur = Vendeur()
    vendeur.run()
