import os
import hashlib
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, utils
from cryptography.x509 import load_pem_x509_certificate


def chiffrer_aes(message: bytes, cle: bytes) -> bytes:
    """AES-256-CBC : IV aleatoire de 16 octets prefixe au texte chiffre."""
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def dechiffrer_aes(message_chiffre: bytes, cle: bytes) -> bytes:
    """AES-256-CBC : extrait l'IV (16 premiers octets) puis dechiffre."""
    iv, data = message_chiffre[:16], message_chiffre[16:]
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def chiffrer_rsa(donnee: bytes, cle_publique) -> bytes:
    """RSA-OAEP (SHA-256) : chiffre la cle AES avec la cle publique du vendeur."""
    return cle_publique.encrypt(
        donnee,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def dechiffrer_rsa(donnee: bytes, cle_privee) -> bytes:
    """RSA-OAEP (SHA-256) : dechiffre la cle AES avec la cle privee du vendeur."""
    return cle_privee.decrypt(
        donnee,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def calculer_hash(message: bytes) -> bytes:
    """Retourne le condensat SHA-1 du message (20 octets)."""
    return hashlib.sha1(message).digest()


def signer(hash_bytes: bytes, cle_privee) -> bytes:
    """Signe un hash SHA-1 pre-calcule avec RSA-PKCS1v15."""
    return cle_privee.sign(
        hash_bytes,
        asym_padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA1())
    )


def verifier_signature(hash_bytes: bytes, signature: bytes, cle_publique) -> bool:
    """Verifie la signature RSA-PKCS1v15 sur un hash SHA-1."""
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


def charger_certificat(chemin: str):
    """Charge un certificat X.509 depuis un fichier PEM."""
    with open(chemin, "rb") as f:
        return load_pem_x509_certificate(f.read())


def verifier_certificat(cert) -> bool:
    """Verifie la periode de validite et la signature autosignee du certificat."""
    try:
        now = datetime.datetime.now(datetime.timezone.utc)

        # Compatibilite cryptography < 42 (naive) et >= 42 (aware)
        try:
            nvb = cert.not_valid_before_utc
            nva = cert.not_valid_after_utc
        except AttributeError:
            nvb = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            nva = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        if now < nvb or now > nva:
            return False

        # Verification de la signature autosignee (emetteur == sujet)
        cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        return True
    except Exception:
        return False
