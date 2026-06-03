import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import cryptography.x509 as x509
from cryptography.x509.oid import NameOID


def generer_cles():
    # Crée le dossier keys/ s'il n'existe pas encore
    os.makedirs("keys", exist_ok=True)

    # 1 : Générer la paire de clés RSA ---
    # une clé publique pour chiffrer,
    # une clé privée  pour déchiffrer.
    
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,  # valeur standard recommandée pour RSA
        key_size=2048,
    )

    # Sauvegarde la clé privée dans un fichier PEM (format texte base64)
    # Cette clé doit rester secrète : seul le vendeur y a accès
    with open("keys/vendeur_private.pem", "wb") as f:
        f.write(cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # pas de mot de passe sur le fichier
        ))

    # Dérive la clé publique depuis la clé privée, puis la sauvegarde
    # La clé publique peut être partagée librement avec tout le monde
    cle_publique = cle_privee.public_key()
    with open("keys/vendeur_public.pem", "wb") as f:
        f.write(cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    #  2 : Créer le certificat X.509 autosigné , contient la clé publique du vendeur + des infos d'identité,
    # le tout signé (ici par lui-même = "autosigné").
    now = datetime.datetime.now(datetime.timezone.utc)

    # Le sujet ET l'émetteur sont identiques → c'est ce qui définit un cert autosigné
    sujet = emetteur = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Boutique MQTT"),
        x509.NameAttribute(NameOID.COMMON_NAME, "vendeur.local"),
    ])

    # Construction du certificat : valable 365 jours à partir de maintenant
    certificat = (
        x509.CertificateBuilder()
        .subject_name(sujet)        # identité du propriétaire du certificat
        .issuer_name(emetteur)      # identité de celui qui a signé (= lui-même)
        .public_key(cle_publique)   # la clé publique embarquée dans le certificat
        .serial_number(x509.random_serial_number())  # numéro unique du certificat
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(cle_privee, hashes.SHA256())  # signature avec la clé privée du vendeur
    )

    # Sauvegarde le certificat (sera envoyé aux acheteurs pendant le handshake)
    with open("keys/vendeur_cert.pem", "wb") as f:
        f.write(certificat.public_bytes(serialization.Encoding.PEM))

    print("[OK] Cle privee   -> keys/vendeur_private.pem")
    print("[OK] Cle publique -> keys/vendeur_public.pem")
    print("[OK] Certificat   -> keys/vendeur_cert.pem")
    print("\nMateriel cryptographique genere avec succes !")


if __name__ == "__main__":
    generer_cles()
