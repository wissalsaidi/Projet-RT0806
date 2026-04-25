import os
import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
import cryptography.x509 as x509
from cryptography.x509.oid import NameOID


def generer_cles():
    os.makedirs("keys", exist_ok=True)

    # Paire de cles RSA 2048 bits
    cle_privee = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open("keys/vendeur_private.pem", "wb") as f:
        f.write(cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    cle_publique = cle_privee.public_key()
    with open("keys/vendeur_public.pem", "wb") as f:
        f.write(cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Certificat X.509 autosigne
    now = datetime.datetime.now(datetime.timezone.utc)
    sujet = emetteur = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Boutique MQTT"),
        x509.NameAttribute(NameOID.COMMON_NAME, "vendeur.local"),
    ])

    certificat = (
        x509.CertificateBuilder()
        .subject_name(sujet)
        .issuer_name(emetteur)
        .public_key(cle_publique)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(cle_privee, hashes.SHA256())
    )

    with open("keys/vendeur_cert.pem", "wb") as f:
        f.write(certificat.public_bytes(serialization.Encoding.PEM))

    print("[OK] Cle privee   -> keys/vendeur_private.pem")
    print("[OK] Cle publique -> keys/vendeur_public.pem")
    print("[OK] Certificat   -> keys/vendeur_cert.pem")
    print("\nMateriel cryptographique genere avec succes !")


if __name__ == "__main__":
    generer_cles()
