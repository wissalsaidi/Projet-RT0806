import os
import hashlib
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, utils
from cryptography.x509 import load_pem_x509_certificate



#  CHIFFREMENT SYMÉTRIQUE — AES-256-CBC
#  Même clé pour chiffrer et déchiffrer.
#  Utilisé pour tous les messages échangés
#  après le handshake (catalogue, commande, confirmation).


def chiffrer_aes(message: bytes, cle: bytes) -> bytes:
    # AES a besoin d'un IV (vecteur d'initialisation) aléatoire de 16 octets.
    # L'IV garantit que chiffrer deux fois le même message donne deux résultats différents.
    iv = os.urandom(16)

    # AES travaille sur des blocs de 16 octets exactement.
    # PKCS7 ajoute des octets de rembourrage pour atteindre un multiple de 16.
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(message) + padder.finalize()

    # Chiffrement AES-256-CBC avec la clé et l'IV générés
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    enc = cipher.encryptor()

    # On préfixe l'IV au message chiffré pour pouvoir déchiffrer plus tard
    return iv + enc.update(padded) + enc.finalize()


def dechiffrer_aes(message_chiffre: bytes, cle: bytes) -> bytes:
    # Les 16 premiers octets = l'IV, le reste = les données chiffrées
    iv, data = message_chiffre[:16], message_chiffre[16:]

    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(data) + dec.finalize()

    # Supprime le rembourrage PKCS7 ajouté lors du chiffrement
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ─────────────────────────────────────────────
#  CHIFFREMENT ASYMÉTRIQUE — RSA
#  Clé publique pour chiffrer, clé privée pour déchiffrer.
#  Utilisé uniquement pendant le handshake pour transmettre
#  la clé AES de façon sécurisée.
# ─────────────────────────────────────────────

def chiffrer_rsa(donnee: bytes, cle_publique) -> bytes:
    # OAEP = mode de padding sécurisé pour RSA (résistant aux attaques classiques)
    # L'acheteur chiffre la clé AES avec la clé publique du vendeur :
    # seul le vendeur (avec sa clé privée) pourra la déchiffrer.
    return cle_publique.encrypt(
        donnee,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def dechiffrer_rsa(donnee: bytes, cle_privee) -> bytes:
    # Le vendeur utilise sa clé privée pour déchiffrer la clé AES
    # envoyée par l'acheteur
    return cle_privee.decrypt(
        donnee,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ─────────────────────────────────────────────
#  INTÉGRITÉ — SHA-1 + SIGNATURE RSA
#  Le hash garantit que le message n'a pas été modifié.
#  La signature prouve que c'est bien le vendeur qui a envoyé.
# ─────────────────────────────────────────────

def calculer_hash(message: bytes) -> bytes:
    # SHA-1 produit une "empreinte" de 20 octets représentant le message.
    # Si un seul octet du message change, l'empreinte est complètement différente.
    return hashlib.sha1(message).digest()


def signer(hash_bytes: bytes, cle_privee) -> bytes:
    # Le vendeur signe l'empreinte SHA-1 avec sa clé privée RSA.
    # N'importe qui avec la clé publique peut vérifier la signature,
    # mais seul le détenteur de la clé privée peut la créer.
    return cle_privee.sign(
        hash_bytes,
        asym_padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA1())  # on passe le hash déjà calculé
    )


def verifier_signature(hash_bytes: bytes, signature: bytes, cle_publique) -> bool:
    # Vérifie que la signature correspond bien au hash et à la clé publique.
    # Retourne True si tout est bon, False si la signature est invalide.
    try:
        cle_publique.verify(
            signature,
            hash_bytes,
            asym_padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA1())
        )
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────
#  CERTIFICAT X.509
#  Le certificat = carte d'identité numérique du vendeur.
#  Il contient sa clé publique + son identité, le tout signé.
# ─────────────────────────────────────────────

def charger_certificat(chemin: str):
    # Lit le fichier .pem et retourne un objet certificat exploitable
    with open(chemin, "rb") as f:
        return load_pem_x509_certificate(f.read())


def verifier_certificat(cert) -> bool:
    # Vérifie deux choses :
    #   1. Le certificat est encore dans sa période de validité (pas expiré)
    #   2. Sa signature est valide (il n'a pas été falsifié)
    try:
        now = datetime.datetime.now(datetime.timezone.utc)

        # Compatibilité entre les versions de la bibliothèque cryptography
        try:
            nvb = cert.not_valid_before_utc
            nva = cert.not_valid_after_utc
        except AttributeError:
            nvb = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            nva = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        # Le certificat est-il dans sa fenêtre de validité ?
        if now < nvb or now > nva:
            return False

        # Vérifie la signature du certificat avec sa propre clé publique (autosigné)
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception:
        return False
