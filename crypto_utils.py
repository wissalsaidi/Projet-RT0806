# =============================================================================
# crypto_utils.py — Boîte à outils cryptographique partagée
# =============================================================================
# Ce module regroupe TOUTES les fonctions de cryptographie utilisées
# par le vendeur et l'acheteur. L'idée : centraliser ici pour ne pas dupliquer
# du code crypto dans chaque fichier (et éviter les erreurs subtiles).
#
# Ce que ce module couvre :
#   - Chiffrement symétrique  : AES-256-CBC (avec IV aléatoire et padding PKCS7)
#   - Chiffrement asymétrique : RSA-2048 avec padding OAEP-SHA256
#   - Intégrité               : hash SHA-1 (empreinte numérique du message)
#   - Authenticité            : signature RSA-PKCS1v15 + vérification
#   - Identité                : chargement et vérification de certificat X.509
# =============================================================================

import os        # pour os.urandom() : génère des bytes vraiment aléatoires
import hashlib   # pour SHA-1
import datetime  # pour vérifier la fenêtre de validité d'un certificat

# Primitives de chiffrement symétrique AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Padding pour AES (PKCS7) et pour RSA (OAEP, PKCS1v15)
from cryptography.hazmat.primitives import padding as sym_padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, utils

# Chargement d'un certificat X.509 depuis le format PEM
from cryptography.x509 import load_pem_x509_certificate


# =============================================================================
# PARTIE 1 — CHIFFREMENT SYMÉTRIQUE (AES-256-CBC)
# =============================================================================
#
# AES (Advanced Encryption Standard) est un chiffrement symétrique :
# la MÊME clé sert à chiffrer ET à déchiffrer.
#
# On utilise la variante AES-256-CBC :
#   - 256 : taille de la clé en bits (= 32 octets) — le niveau de sécurité maximal
#   - CBC : "Cipher Block Chaining" — chaque bloc chiffré dépend du précédent,
#           ce qui empêche de retrouver des patterns si le même texte est chiffré plusieurs fois
#
# AES est utilisé APRÈS le handshake pour chiffrer :
#   - le catalogue (vendeur → acheteur)
#   - la commande (acheteur → vendeur)
#   - la confirmation (vendeur → acheteur)
# =============================================================================

def chiffrer_aes(message: bytes, cle: bytes) -> bytes:
    """
    Chiffre un message en AES-256-CBC et retourne : IV (16 octets) + données chiffrées.

    Pourquoi préfixer l'IV ?
    → Le destinataire a besoin de l'IV pour déchiffrer, et l'IV n'est pas secret.
      On l'intègre directement au début du message chiffré pour tout garder ensemble.
    """

    # --- Génération de l'IV (vecteur d'initialisation) ---
    # AES-CBC a besoin d'un "grain de sel" aléatoire de 16 octets appelé IV.
    # Son rôle : si on chiffre deux fois le même message avec la même clé,
    # l'IV différent à chaque fois garantit que le résultat chiffré est différent.
    # Sans IV, un attaquant pourrait détecter que deux messages sont identiques.
    iv = os.urandom(16)  # 16 octets = 128 bits, taille fixe imposée par AES-CBC

    # --- Padding PKCS7 ---
    # AES travaille UNIQUEMENT sur des blocs de 16 octets (128 bits).
    # Si le message n'est pas un multiple de 16 octets, on doit l'allonger.
    # PKCS7 ajoute N octets de valeur N pour compléter jusqu'au prochain multiple de 16.
    # Exemple : message de 13 octets → on ajoute 3 octets valant 0x03
    #
    # Le "128" ici est la taille du bloc en BITS (= 16 octets), pas en bytes.
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(message) + padder.finalize()

    # --- Chiffrement AES-256-CBC ---
    # On crée l'objet Cipher avec l'algorithme AES (notre clé 256 bits)
    # et le mode CBC (avec l'IV généré juste au-dessus).
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    enc = cipher.encryptor()

    # update() traite les données, finalize() chiffre le dernier bloc
    donnees_chiffrees = enc.update(padded) + enc.finalize()

    # On retourne IV + données chiffrées collés ensemble.
    # Le destinataire sait que les 16 premiers octets = l'IV, le reste = les données.
    return iv + donnees_chiffrees


def dechiffrer_aes(message_chiffre: bytes, cle: bytes) -> bytes:
    """
    Déchiffre un message AES-256-CBC préalablement chiffré par chiffrer_aes().

    Le message_chiffre est de la forme : IV (16 octets) + données chiffrées.
    On extrait l'IV, déchiffre, puis supprime le padding PKCS7.
    """

    # --- Extraction de l'IV ---
    # Les 16 premiers octets sont toujours l'IV (convention établie dans chiffrer_aes)
    iv = message_chiffre[:16]
    donnees = message_chiffre[16:]  # tout le reste = les données chiffrées

    # --- Déchiffrement AES-256-CBC ---
    # Même configuration qu'au chiffrement, mais avec le decryptor()
    cipher = Cipher(algorithms.AES(cle), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(donnees) + dec.finalize()

    # --- Suppression du padding PKCS7 ---
    # On retire les octets de rembourrage ajoutés lors du chiffrement
    # pour récupérer le message original exact.
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# =============================================================================
# PARTIE 2 — CHIFFREMENT ASYMÉTRIQUE (RSA-2048)
# =============================================================================
#
# RSA utilise une PAIRE de clés :
#   - clé PUBLIQUE  : partagée avec tout le monde, sert à CHIFFRER
#   - clé PRIVÉE    : gardée secrète, sert à DÉCHIFFRER
#
# Dans notre protocole, RSA est utilisé UNIQUEMENT pendant le handshake
# pour transmettre la clé AES de façon sécurisée :
#   Acheteur → chiffre la clé AES avec la clé publique du vendeur
#   Vendeur  → déchiffre avec sa clé privée
#
# RSA n'est pas utilisé pour chiffrer les données en continu car il est
# beaucoup plus lent qu'AES. C'est pourquoi on fait un "handshake RSA"
# juste pour partager une clé AES, puis on bascule sur AES pour tout le reste.
# (C'est exactement ce que fait TLS dans un vrai protocole réseau !)
# =============================================================================

def chiffrer_rsa(donnee: bytes, cle_publique) -> bytes:
    """
    Chiffre des données avec une clé publique RSA en utilisant le padding OAEP.

    Pourquoi OAEP et pas le padding simple ?
    OAEP (Optimal Asymmetric Encryption Padding) est un padding sécurisé
    qui rend RSA résistant aux attaques de type "chosen ciphertext".
    Le padding simple (PKCS1v15 pour le chiffrement) est considéré vulnérable
    depuis les années 90 — ne jamais l'utiliser pour du chiffrement.
    """
    return cle_publique.encrypt(
        donnee,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),  # fonction de masque basée sur SHA-256
            algorithm=hashes.SHA256(),  # algorithme de hash utilisé dans OAEP
            label=None  # label optionnel, rarement utilisé, on laisse None
        )
    )


def dechiffrer_rsa(donnee: bytes, cle_privee) -> bytes:
    """
    Déchiffre des données RSA-OAEP avec la clé privée correspondante.

    Seul le détenteur de la clé privée peut appeler cette fonction avec succès.
    Si on essaie de déchiffrer avec une mauvaise clé, une exception sera levée.
    """
    return cle_privee.decrypt(
        donnee,
        asym_padding.OAEP(
            # Les mêmes paramètres qu'au chiffrement (obligatoire, sinon ça échoue)
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# =============================================================================
# PARTIE 3 — INTÉGRITÉ ET AUTHENTICITÉ (SHA-1 + SIGNATURE RSA)
# =============================================================================
#
# Le hash et la signature servent à deux choses différentes :
#
#   SHA-1 seul (hash brut) → INTÉGRITÉ uniquement
#     "Le message n'a pas été modifié en transit"
#     (utilisé pour les commandes de l'acheteur qui n'a pas de clé privée)
#
#   SHA-1 + signature RSA → INTÉGRITÉ + AUTHENTICITÉ
#     "Le message vient bien du vendeur ET n'a pas été modifié"
#     (utilisé pour le catalogue et la confirmation)
#
# SHA-1 est considéré comme faible pour les nouvelles applications (2017+)
# mais reste acceptable pour de l'intégrité non critique dans un contexte éducatif.
# En production, on utiliserait SHA-256 ou SHA-3.
# =============================================================================

def calculer_hash(message: bytes) -> bytes:
    """
    Calcule l'empreinte SHA-1 d'un message et retourne 20 octets.

    SHA-1 produit une "empreinte digitale" de 160 bits (20 octets) du message.
    Propriété importante : si on change un seul bit du message,
    l'empreinte change complètement (effet avalanche).
    Deux messages différents ne peuvent (en théorie) pas avoir la même empreinte.
    """
    # hashlib.sha1() crée l'objet de hachage
    # .digest() retourne le résultat en bytes bruts (vs .hexdigest() qui retourne une chaîne hex)
    return hashlib.sha1(message).digest()  # 20 octets


def signer(hash_bytes: bytes, cle_privee) -> bytes:
    """
    Signe une empreinte SHA-1 avec la clé privée RSA du vendeur.

    La signature = "preuve que le détenteur de la clé privée a validé ce message".
    On signe le HASH et non le message original pour deux raisons :
      1. RSA ne peut chiffrer que des données inférieures à la taille de la clé (2048 bits)
      2. Hacher d'abord est plus rapide et ne compromet pas la sécurité
    """
    return cle_privee.sign(
        hash_bytes,
        asym_padding.PKCS1v15(),  # padding PKCS1v15 est acceptable pour la SIGNATURE (pas pour le chiffrement)
        utils.Prehashed(hashes.SHA1())  # on indique que le hash est déjà calculé (Prehashed)
        # sans Prehashed, la bibliothèque re-hasherait les données → double hachage incorrect
    )


def verifier_signature(hash_bytes: bytes, signature: bytes, cle_publique) -> bool:
    """
    Vérifie qu'une signature RSA correspond au hash donné avec la clé publique.

    Retourne True si la signature est valide, False sinon.
    On utilise un try/except car la bibliothèque lève une exception plutôt que
    de retourner False en cas de signature invalide (comportement standard en crypto).
    """
    try:
        # verify() ne retourne rien si c'est bon, lève InvalidSignature si c'est faux
        cle_publique.verify(
            signature,
            hash_bytes,
            asym_padding.PKCS1v15(),
            utils.Prehashed(hashes.SHA1())
        )
        return True  # la signature est valide : le message est authentique et intègre
    except Exception:
        # Soit la signature est invalide, soit les paramètres sont mauvais.
        # Dans tous les cas, on retourne False → le message ne doit pas être accepté.
        return False


# =============================================================================
# PARTIE 4 — CERTIFICAT X.509
# =============================================================================
#
# Un certificat X.509 est la "carte d'identité numérique" du vendeur.
# Il contient :
#   - Le nom/organisation du titulaire
#   - Sa clé publique RSA
#   - La période de validité (date de début et date de fin)
#   - La signature de l'émetteur (ici autosigné = le vendeur signe son propre certificat)
#
# L'acheteur reçoit ce certificat pendant le handshake et doit :
#   1. Vérifier que le certificat n'est pas expiré
#   2. Vérifier que sa signature est correcte (qu'il n'a pas été falsifié)
#   3. En extraire la clé publique pour chiffrer la clé AES
# =============================================================================

def charger_certificat(chemin: str):
    """
    Charge un certificat X.509 depuis un fichier PEM et retourne l'objet Python.

    Utilisé principalement par le vendeur au démarrage pour charger son certificat.
    Retourne un objet Certificate exploitable (avec .public_key(), .not_valid_after_utc, etc.)
    """
    with open(chemin, "rb") as f:
        return load_pem_x509_certificate(f.read())


def verifier_certificat(cert) -> bool:
    """
    Vérifie la validité d'un certificat X.509.

    Deux vérifications sont effectuées :
      1. Temporelle : le certificat est-il dans sa fenêtre de validité ?
         (not_valid_before <= maintenant <= not_valid_after)
      2. Cryptographique : la signature du certificat est-elle correcte ?
         (pour un cert autosigné, on vérifie avec sa propre clé publique)

    Retourne True si les deux vérifications passent, False sinon.
    """
    try:
        # On récupère l'heure actuelle en UTC avec timezone pour la comparaison
        now = datetime.datetime.now(datetime.timezone.utc)

        # --- Compatibilité entre versions de la bibliothèque cryptography ---
        # Depuis cryptography 42.x, les attributs s'appellent not_valid_before_utc
        # et not_valid_after_utc (timezone-aware).
        # Les versions plus anciennes utilisent not_valid_before/after (timezone-naive).
        # On essaie d'abord la nouvelle API, et on retombe sur l'ancienne si besoin.
        try:
            nvb = cert.not_valid_before_utc  # date de début de validité (nouveau nom)
            nva = cert.not_valid_after_utc   # date de fin de validité (nouveau nom)
        except AttributeError:
            # Ancienne API : les dates sont "naive" (sans timezone), on ajoute UTC manuellement
            nvb = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            nva = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

        # Vérifie que la date actuelle est bien dans la fenêtre de validité
        # Si le certificat est trop tôt (avant nvb) ou expiré (après nva) → False
        if now < nvb or now > nva:
            return False  # certificat hors de sa fenêtre de validité

        # --- Vérification de la signature du certificat ---
        # Pour un certificat autosigné (comme le nôtre), l'émetteur = le titulaire.
        # On vérifie que la signature du certificat correspond à sa propre clé publique.
        # Si quelqu'un a modifié le certificat (nom, clé, dates...), la signature ne correspondra plus.
        cert.public_key().verify(
            cert.signature,              # la signature stockée dans le certificat
            cert.tbs_certificate_bytes,  # les données signées (le "corps" du certificat)
            asym_padding.PKCS1v15(),     # padding utilisé lors de la signature
            cert.signature_hash_algorithm  # algorithme de hash utilisé (SHA-256 dans notre cas)
        )

        return True  # le certificat est valide : dans sa période de validité et non falsifié

    except Exception:
        # verify() a levé une exception → soit la signature est invalide,
        # soit les paramètres sont incorrects. Dans tous les cas, le certificat est rejeté.
        return False
