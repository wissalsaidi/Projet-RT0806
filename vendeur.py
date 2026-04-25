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
    """Cree un client MQTT compatible paho-mqtt 1.x et 2.x."""
    try:
        return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    except AttributeError:
        return mqtt.Client(client_id=client_id)


class Vendeur:
    def __init__(self):
        with open("keys/vendeur_private.pem", "rb") as f:
            self.cle_privee = serialization.load_pem_private_key(f.read(), password=None)
        with open("keys/vendeur_cert.pem", "rb") as f:
            self.cert_pem = f.read()

        # Dictionnaire buyer_id -> cle_aes pour gerer plusieurs acheteurs
        self.sessions = {}

        self.client = _creer_client_mqtt("vendeur")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc):
        print(f"[Vendeur] Connecte au broker MQTT (code={rc})")
        client.subscribe("shop/handshake/request")
        client.subscribe("shop/handshake/key/+")
        client.subscribe("shop/commande/+")
        print("[Vendeur] En attente d'acheteurs...\n")

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        try:
            if topic == "shop/handshake/request":
                self._handle_request(msg.payload)
            elif topic.startswith("shop/handshake/key/"):
                buyer_id = topic.split("/")[-1]
                self._handle_key(buyer_id, msg.payload)
            elif topic.startswith("shop/commande/"):
                buyer_id = topic.split("/")[-1]
                self._handle_commande(buyer_id, msg.payload)
        except Exception as e:
            print(f"[Vendeur] Erreur traitement message sur '{topic}': {e}")

    def _handle_request(self, payload):
        data = json.loads(payload)
        buyer_id = data["buyer_id"]
        print(f"[Vendeur] Demande de connexion de l'acheteur '{buyer_id}'")
        # Envoie le certificat X.509 sur le topic dedie a cet acheteur
        self.client.publish(f"shop/handshake/cert/{buyer_id}", self.cert_pem)
        print(f"[Vendeur] Certificat X.509 envoye a '{buyer_id}'")

    def _handle_key(self, buyer_id, payload):
        # L'acheteur envoie la cle AES chiffree en RSA (base64)
        aes_key_chiffree = base64.b64decode(payload)
        aes_key = dechiffrer_rsa(aes_key_chiffree, self.cle_privee)
        self.sessions[buyer_id] = aes_key
        print(f"[Vendeur] Cle AES-256 dechiffree pour '{buyer_id}' — session etablie")
        self._envoyer_catalogue(buyer_id)

    def _envoyer_catalogue(self, buyer_id):
        aes_key = self.sessions[buyer_id]
        catalogue_bytes = json.dumps(CATALOGUE, ensure_ascii=False).encode()

        data_chiffre = chiffrer_aes(catalogue_bytes, aes_key)
        hash_msg = calculer_hash(catalogue_bytes)
        signature = signer(hash_msg, self.cle_privee)

        message = json.dumps({
            "data": base64.b64encode(data_chiffre).decode(),
            "hash": base64.b64encode(signature).decode(),
            "cert": self.cert_pem.decode()
        })
        self.client.publish(f"shop/catalogue/{buyer_id}", message)
        print(f"[Vendeur] Catalogue chiffre (AES-256) envoye a '{buyer_id}'")

    def _handle_commande(self, buyer_id, payload):
        if buyer_id not in self.sessions:
            print(f"[Vendeur] Session inconnue pour '{buyer_id}' — commande ignoree")
            return

        aes_key = self.sessions[buyer_id]
        msg = json.loads(payload)

        # Dechiffrement AES de la commande
        contenu = dechiffrer_aes(base64.b64decode(msg["data"]), aes_key)

        # Verification de l'integrite par SHA-1 (l'acheteur n'a pas de cle privee)
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
        confirmation = {
            "statut": "OK",
            "message": f"Commande confirmee : {commande['nom']} a {commande['prix']}EUR",
            "reference": f"CMD-{buyer_id[:8].upper()}"
        }
        conf_bytes = json.dumps(confirmation, ensure_ascii=False).encode()
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
        self.client.connect(BROKER, PORT)
        self.client.loop_forever()


if __name__ == "__main__":
    vendeur = Vendeur()
    vendeur.run()
