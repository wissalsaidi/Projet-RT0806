# Simulation Vendeur / Acheteur sécurisé via MQTT

Projet de réseau et télécommunications — Simulation d'un mini tunnel TLS "maison" entre un vendeur et des acheteurs, communiquant via le protocole MQTT.

---

## Objectif

Mettre en œuvre une communication **chiffrée et authentifiée** entre un serveur (vendeur) et des clients (acheteurs) via un broker MQTT (Mosquitto), **sans utiliser le TLS automatique du réseau**.

Toute la sécurité est implémentée manuellement en Python :
- Échange de clé par **RSA 2048**
- Chiffrement des messages par **AES-256**
- Vérification de l'intégrité par **SHA-1**
- Authentification par **certificat X.509 autosigné**

---

## Architecture du projet

```
mon-projet-mqtt/
│
├── generate_keys.py      ← Génère les clés RSA + certificat (à lancer 1 seule fois)
├── crypto_utils.py       ← Fonctions de crypto partagées (AES, RSA, SHA-1, X.509)
├── vendeur.py            ← Le serveur / vendeur
├── acheteur.py           ← Le client / acheteur
│
└── keys/                 ← Créé automatiquement par generate_keys.py
    ├── vendeur_private.pem
    ├── vendeur_public.pem
    └── vendeur_cert.pem
```

---

## Prérequis

### Logiciels
- **Python 3.8+**
- **Mosquitto** (broker MQTT) — installé dans `C:\Program Files\mosquitto\`

### Bibliothèques Python
```bash
pip install paho-mqtt cryptography
```

---

## Lancement

### Étape 1 — Générer les clés (une seule fois)
```bash
python generate_keys.py
```
Crée le dossier `keys/` avec la clé privée RSA, la clé publique et le certificat X.509.

### Étape 2 — Ouvrir 3 terminaux

**Terminal 1 — Broker MQTT :**
```bash
& "C:\Program Files\mosquitto\mosquitto.exe" -v
```

**Terminal 2 — Vendeur :**
```bash
python vendeur.py
```

**Terminal 3 — Acheteur :**
```bash
python acheteur.py
```

L'acheteur affiche le catalogue, vous choisissez un produit, et la commande est envoyée de façon sécurisée. Les messages visibles dans Mosquitto sont illisibles (chiffrés).

---

## Fonctionnement détaillé

### Le handshake (établissement de la session sécurisée)

```
Acheteur                              Vendeur
   │                                     │
   │── "Je veux me connecter" ──────────►│  shop/handshake/request
   │                                     │
   │◄── Certificat X.509 ───────────────│  shop/handshake/cert/{id}
   │                                     │
   │  Vérifie le certificat              │
   │  Extrait la clé publique RSA        │
   │  Génère une clé AES-256 aléatoire   │
   │  Chiffre la clé AES avec RSA        │
   │                                     │
   │── Clé AES chiffrée (RSA) ─────────►│  shop/handshake/key/{id}
   │                                     │
   │  Le vendeur déchiffre avec          │
   │  sa clé privée RSA                  │
   │                                     │
   │◄══════ Communication AES-256 ══════►│  (tout chiffré à partir d'ici)
```

### Les topics MQTT

| Topic | Émetteur | Contenu |
|---|---|---|
| `shop/handshake/request` | Acheteur | Demande de connexion (buyer_id) |
| `shop/handshake/cert/{id}` | Vendeur | Certificat X.509 |
| `shop/handshake/key/{id}` | Acheteur | Clé AES chiffrée en RSA |
| `shop/catalogue/{id}` | Vendeur | Catalogue chiffré en AES |
| `shop/commande/{id}` | Acheteur | Commande chiffrée en AES |
| `shop/confirmation/{id}` | Vendeur | Confirmation chiffrée en AES |

> Le `{id}` dans les topics est l'identifiant unique de chaque acheteur, ce qui permet à plusieurs acheteurs de se connecter simultanément, chacun avec sa propre session AES.

### Format d'un message sécurisé (JSON)

```json
{
  "data": "<contenu chiffré AES-256, encodé en base64>",
  "hash": "<SHA-1 du message original, signé RSA, encodé en base64>",
  "cert": "<certificat X.509 du vendeur en PEM>"
}
```

**Ordre de vérification à la réception :**
1. Vérifier le certificat X.509 (validité + signature autosignée)
2. Déchiffrer `data` avec AES-256 et la clé de session
3. Recalculer SHA-1 sur le message déchiffré et vérifier la signature RSA

---

## Description des fichiers

### `generate_keys.py`
- Génère une paire de clés **RSA 2048 bits**
- Crée un **certificat X.509 autosigné** valable 1 an (avec la clé publique du vendeur)
- Sauvegarde tout dans `keys/`

### `crypto_utils.py`

| Fonction | Description |
|---|---|
| `chiffrer_aes(message, cle)` | AES-256-CBC avec IV aléatoire (préfixé) |
| `dechiffrer_aes(chiffre, cle)` | Extrait l'IV puis déchiffre |
| `chiffrer_rsa(donnee, cle_pub)` | RSA-OAEP SHA-256 |
| `dechiffrer_rsa(donnee, cle_priv)` | RSA-OAEP SHA-256 |
| `calculer_hash(message)` | SHA-1 → 20 octets |
| `signer(hash, cle_privee)` | RSA-PKCS1v15 sur hash pré-calculé |
| `verifier_signature(hash, sig, cle_pub)` | Retourne True/False |
| `charger_certificat(chemin)` | Charge un fichier `.pem` |
| `verifier_certificat(cert)` | Vérifie validité + signature autosignée |

### `vendeur.py`
- Se connecte à Mosquitto et écoute les demandes
- Gère les sessions de plusieurs acheteurs simultanément (`buyer_id → clé AES`)
- Pour chaque acheteur : envoie le certificat → reçoit la clé AES → envoie le catalogue → confirme les commandes
- Tous les messages envoyés sont **signés RSA + chiffrés AES**

### `acheteur.py`
- Génère un `BUYER_ID` unique à chaque lancement
- Effectue le handshake : vérifie le certificat, génère et envoie la clé AES
- Affiche le catalogue dans le terminal
- Chiffre la commande en AES-256 avec contrôle d'intégrité SHA-1
- Affiche la confirmation finale

---

## Technologies utilisées

| Technologie | Rôle |
|---|---|
| **MQTT** | Protocole de messagerie léger (publish/subscribe) |
| **Mosquitto** | Broker MQTT (le relais entre les clients) |
| **RSA 2048** | Chiffrement asymétrique pour l'échange de la clé AES |
| **AES-256-CBC** | Chiffrement symétrique des messages (clé de session) |
| **SHA-1** | Hash pour l'intégrité des messages |
| **X.509** | Certificat numérique pour authentifier le vendeur |
| **paho-mqtt** | Bibliothèque Python pour MQTT |
| **cryptography** | Bibliothèque Python pour RSA, AES, X.509, SHA-1 |

---

## Catalogue des produits

| # | Produit | Prix |
|---|---|---|
| 1 | Clavier | 49 € |
| 2 | Souris | 29 € |
| 3 | Écran 27 pouces | 299 € |
| 4 | Casque audio | 79 € |
| 5 | Webcam HD | 59 € |
| 6 | Clé USB 64 Go | 12 € |
| 7 | Câble HDMI | 15 € |
| 8 | Tapis souris | 19 € |
| 9 | Hub USB | 35 € |
| 10 | Support PC | 45 € |

---

## Choix de conception

**Pourquoi des topics avec `{buyer_id}` ?**
Chaque acheteur a sa propre clé AES de session. Sans identifiant dans les topics, le vendeur ne pourrait pas router les messages vers le bon acheteur.

**Pourquoi l'acheteur ne signe pas ses commandes ?**
Dans cette simulation, seul le vendeur possède une paire de clés RSA. L'intégrité des commandes envoyées par l'acheteur est assurée par un hash SHA-1 simple (non signé). En production, chaque partie aurait ses propres clés.

**Pourquoi AES-CBC avec IV aléatoire ?**
L'IV (vecteur d'initialisation) aléatoire garantit que deux chiffrements du même message donnent des résultats différents, empêchant l'analyse de patterns.
