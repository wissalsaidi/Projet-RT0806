# =============================================================================
# generate_keys.py — Génération du matériel cryptographique du vendeur
# =============================================================================
# Ce script est à lancer UNE SEULE FOIS avant de démarrer le vendeur.
# Il génère trois fichiers dans le dossier keys/ :
#
#   vendeur_private.pem  → clé privée RSA 2048 bits (SECRET — ne jamais partager !)
#   vendeur_public.pem   → clé publique RSA correspondante (peut être partagée)
#   vendeur_cert.pem     → certificat X.509 autosigné valable 1 an
#
# Pourquoi trois fichiers ?
#   - La clé privée sert à déchiffrer la clé AES et à signer les messages
#   - La clé publique est dérivée de la clé privée (redondant mais pratique)
#   - Le certificat = la clé publique + identité du vendeur + signature → envoyé aux acheteurs
#
# Note : ce certificat est "autosigné", ce qui signifie que le vendeur signe
# son propre certificat. En production, un tiers de confiance (CA) signerait
# ce certificat pour garantir l'identité. Ici on se fait confiance à nous-mêmes
# car c'est un environnement de simulation fermé.
# =============================================================================

import os        # pour créer le dossier keys/ s'il n'existe pas
import datetime  # pour définir la période de validité du certificat

# Primitives RSA de la bibliothèque cryptography
from cryptography.hazmat.primitives.asymmetric import rsa

# Pour sérialiser les clés en format PEM (format texte lisible)
from cryptography.hazmat.primitives import serialization, hashes

# Pour construire le certificat X.509
import cryptography.x509 as x509
from cryptography.x509.oid import NameOID  # constantes pour les champs d'identité (pays, org, etc.)


def generer_cles():
    """
    Génère et sauvegarde la paire de clés RSA + le certificat X.509 autosigné.

    Cette fonction crée le dossier keys/ si besoin, puis enchaîne :
      1. Génération de la paire de clés RSA 2048 bits
      2. Sauvegarde de la clé privée dans keys/vendeur_private.pem
      3. Dérivation et sauvegarde de la clé publique dans keys/vendeur_public.pem
      4. Construction et sauvegarde du certificat X.509 dans keys/vendeur_cert.pem
    """

    # Crée le dossier keys/ s'il n'existe pas encore.
    # exist_ok=True évite l'erreur si le dossier existe déjà
    # (pratique si on relance le script pour regénérer les clés)
    os.makedirs("keys", exist_ok=True)

    # =========================================================================
    # ÉTAPE 1 — GÉNÉRATION DE LA PAIRE DE CLÉS RSA
    # =========================================================================
    #
    # RSA (Rivest–Shamir–Adleman) est un algorithme de chiffrement asymétrique.
    # Il génère deux clés mathématiquement liées :
    #   - clé PRIVÉE : garde secrète, utilisée pour DÉCHIFFRER et SIGNER
    #   - clé PUBLIQUE : partageable, utilisée pour CHIFFRER et VÉRIFIER
    #
    # Paramètres choisis :
    #   public_exponent = 65537 : valeur standard et recommandée pour RSA.
    #     C'est un nombre premier de Fermat (2^16 + 1) qui offre un bon équilibre
    #     entre vitesse et sécurité. Presque tout le monde utilise 65537.
    #   key_size = 2048 : taille de la clé en bits. 2048 est le minimum recommandé
    #     aujourd'hui pour RSA. 4096 est plus sûr mais beaucoup plus lent.
    # =========================================================================

    print("Génération de la paire de clés RSA 2048 bits...")

    cle_privee = rsa.generate_private_key(
        public_exponent=65537,  # valeur standard universellement recommandée
        key_size=2048,          # 2048 bits = niveau de sécurité suffisant pour notre usage
    )

    # =========================================================================
    # SAUVEGARDE DE LA CLÉ PRIVÉE
    # =========================================================================
    #
    # On sérialise la clé en format PEM (Privacy Enhanced Mail).
    # Le PEM est un format texte base64 avec des balises -----BEGIN / -----END-----
    # reconnaissable par tous les outils crypto.
    #
    # PKCS8 est le format de sérialisation recommandé pour les clés privées.
    # NoEncryption() : la clé n'est PAS protégée par un mot de passe.
    # Dans un vrai système en production, on utiliserait BestAvailableEncryption(b"mot_de_passe")
    # pour protéger la clé en cas de vol du fichier.
    # =========================================================================

    with open("keys/vendeur_private.pem", "wb") as f:
        f.write(cle_privee.private_bytes(
            encoding=serialization.Encoding.PEM,              # format PEM (texte base64)
            format=serialization.PrivateFormat.PKCS8,         # structure PKCS#8 standard
            encryption_algorithm=serialization.NoEncryption() # pas de mot de passe (simplification)
        ))

    print("[OK] Cle privee   -> keys/vendeur_private.pem")

    # =========================================================================
    # SAUVEGARDE DE LA CLÉ PUBLIQUE
    # =========================================================================
    #
    # La clé publique est DÉRIVÉE de la clé privée (on ne la génère pas indépendamment).
    # Elle peut être partagée librement — c'est justement son rôle.
    # SubjectPublicKeyInfo est le format standard pour les clés publiques PEM.
    # =========================================================================

    cle_publique = cle_privee.public_key()  # dérive la clé publique depuis la clé privée

    with open("keys/vendeur_public.pem", "wb") as f:
        f.write(cle_publique.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo  # format standard pour les clés publiques
        ))

    print("[OK] Cle publique -> keys/vendeur_public.pem")

    # =========================================================================
    # ÉTAPE 2 — CRÉATION DU CERTIFICAT X.509 AUTOSIGNÉ
    # =========================================================================
    #
    # Un certificat X.509 est une structure standardisée qui contient :
    #   - L'identité du titulaire (pays, organisation, nom commun)
    #   - La clé publique RSA du titulaire
    #   - La période de validité (from → to)
    #   - Un numéro de série unique
    #   - Une signature cryptographique de tout ce qui précède
    #
    # "Autosigné" = l'émetteur (issuer) et le sujet (subject) sont identiques.
    # Le vendeur signe son propre certificat avec sa clé privée.
    # En production, un CA (Certificate Authority) comme Let's Encrypt ou
    # Comodo signerait le certificat, ce qui permettrait à n'importe qui
    # de vérifier l'identité sans connaître le vendeur à l'avance.
    # =========================================================================

    # Date et heure actuelles en UTC (timezone-aware, requis par la bibliothèque)
    now = datetime.datetime.now(datetime.timezone.utc)

    # Définition de l'identité du vendeur (champs standard X.509)
    # Pour un cert autosigné, sujet ET émetteur sont identiques
    sujet = emetteur = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),             # pays : France
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Boutique MQTT"),  # organisation
        x509.NameAttribute(NameOID.COMMON_NAME, "vendeur.local"),   # nom commun (souvent le domaine)
    ])

    # Construction du certificat avec le pattern builder (fluent interface)
    certificat = (
        x509.CertificateBuilder()

        # Identité du titulaire du certificat (c'est le vendeur lui-même)
        .subject_name(sujet)

        # Identité de celui qui a signé le certificat
        # Pour un cert autosigné, c'est la même entité que le sujet
        .issuer_name(emetteur)

        # La clé publique RSA à certifier (c'est elle que les acheteurs utiliseront)
        .public_key(cle_publique)

        # Numéro de série unique, généré aléatoirement
        # Chaque certificat doit avoir un numéro unique pour pouvoir être révoqué individuellement
        .serial_number(x509.random_serial_number())

        # Date de début de validité : maintenant (à la seconde près)
        .not_valid_before(now)

        # Date de fin de validité : dans exactement 365 jours
        # Après cette date, les acheteurs refuseront ce certificat
        .not_valid_after(now + datetime.timedelta(days=365))

        # Extension BasicConstraints : ca=True indique que ce certificat peut lui-même
        # signer d'autres certificats (utile pour vérifier un cert autosigné)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True  # critical=True : tout client qui ne comprend pas cette extension DOIT rejeter le cert
        )

        # Signature finale avec la clé privée du vendeur et SHA-256 comme algorithme de hash
        # C'est cette étape qui "scelle" le certificat — toute modification après ça
        # invalide la signature
        .sign(cle_privee, hashes.SHA256())
    )

    # Sauvegarde du certificat en format PEM
    # Ce fichier sera envoyé tel quel aux acheteurs pendant le handshake
    with open("keys/vendeur_cert.pem", "wb") as f:
        f.write(certificat.public_bytes(serialization.Encoding.PEM))

    print("[OK] Certificat   -> keys/vendeur_cert.pem")
    print("\nMateriel cryptographique genere avec succes !")
    print("Pensez a relancer le vendeur si les anciennes cles etaient deja en cours d'utilisation.")


# =============================================================================
# POINT D'ENTRÉE
# =============================================================================

if __name__ == "__main__":
    # On lance la génération uniquement si ce fichier est exécuté directement
    # (pas si importé par un autre module, ex. dans des tests)
    generer_cles()
