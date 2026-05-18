<p align="center">
  <img src="./Presentation_web.jpg" alt="Seecret.it logo">
</p>

<h1>📦 Seecret.it — Version auto-hébergée</h1>

![Status](https://img.shields.io/badge/Project-Active-brightgreen)
![Security](https://img.shields.io/badge/Encrypted-Yes-blue)
![Stack](https://img.shields.io/badge/Stack-PHP%20%2B%20SQLite-orange)
![JS](https://img.shields.io/badge/JavaScript-Vanilla-yellow)

Une version **open-source minimaliste** de [Seecret.it](https://seecret.it) — frontend en **vanilla JavaScript**, backend en **PHP + SQLite** (un seul fichier). Aucun framework, aucun NPM, aucune dépendance Composer. À déployer en 30 secondes sur n’importe quel hébergement mutualisé.

> 💡 Cette version est volontairement épurée. Pour les fonctionnalités complètes (upload de fichiers, comptes utilisateurs, statistiques, extensions Thunderbird/navigateur, QR Codes Wi-Fi, etc.), utilisez le service hébergé [seecret.it](https://seecret.it).

<h1>🔐 Fonctionnalités</h1>

- Chiffrement **AES-GCM 256 bits** côté client (Web Crypto API native)
- Lien à **usage unique** : le secret est détruit dès la première lecture (transaction SQLite atomique)
- **Expiration configurable** : 5 min / 1h / 1j / 7j / 30j
- **Mot de passe optionnel** avec dérivation **PBKDF2 (600 000 itérations, SHA-256)** — OWASP 2023
- **Gate anti-robot** (case à cocher + bouton) pour éviter le déclenchement par les previews de liens (Discord, Slack, WhatsApp, etc.)
- Modèle **zéro-knowledge** : la clé de déchiffrement ne quitte jamais le navigateur

<h1>🧠 Pourquoi zéro-knowledge ?</h1>

Le serveur ne stocke que le **ciphertext**. La clé (ou le sel PBKDF2 si mot de passe) reste dans le **fragment `#` de l'URL** — partie qui, par spécification HTTP, **n'est jamais envoyée au serveur**.

Conséquence : même si la base est compromise, **personne ne peut déchiffrer** les secrets stockés sans posséder l'URL complète.

```
https://votre-domaine.tld/view.html#i=abc12_xy&v=1&p=0&k=BASE64KEY
                                    └─────────────┬─────────────┘
                                    Cette partie reste côté client
```

<h1>🛠️ Stack</h1>

- HTML / CSS / **Vanilla JavaScript** — aucun framework
- [Bootstrap 5](https://getbootstrap.com/) (CSS, en local)
- [SweetAlert2](https://sweetalert2.github.io/) (en local)
- [Web Crypto API](https://developer.mozilla.org/fr/docs/Web/API/Web_Crypto_API) (natif navigateur)
- **PHP ≥ 8.0** + extension `pdo_sqlite` (paquet `php-sqlite3` sur Debian/Ubuntu)

<h1>🚀 Installation</h1>

```bash
git clone https://github.com/Seecret-it/seecret.it.git
cd seecret.it/versionAutoHeberge

# Lancer en local
php -S localhost:8000
```

Ou pointer le `DocumentRoot` Apache/Nginx vers ce dossier. Le répertoire `data/` est créé automatiquement au premier appel — vérifiez juste que l'utilisateur PHP a les droits d'écriture dessus.

<h1>📁 Structure</h1>

```
versionAutoHeberge/
├── index.html          Page de création
├── view.html           Page de lecture
├── api.php             API REST : POST (créer) / GET (lire + détruire)
├── data/
│   ├── .htaccess       Bloque l'accès direct à seecrets.sqlite
│   └── .gitignore      Ignore le .sqlite (ne pas commiter la BDD)
├── css/
│   ├── bootstrap.min.css
│   ├── sweetalert.css
│   └── style.css       Thème seecret.it (cyan #4ac4f3 + turquoise #1aebd6)
└── js/
    ├── bootstrap.bundle.min.js
    ├── sweetalert.js
    ├── crypto.js       AES-GCM + PBKDF2 (Web Crypto API)
    ├── app.js          Logique page de création
    └── view.js         Logique page de lecture
```

<h1>🔗 API</h1>

### Créer un secret

```http
POST /api.php
Content-Type: application/json

{
  "ciphertext": "base64url",
  "expires_in": 86400
}
```

**Réponse :**
```json
{ "id": "abc12_xy", "expires_at": 1746790000 }
```

### Lire un secret (et le détruire)

```http
GET /api.php?id=abc12_xy
```

**Réponse** (le secret est immédiatement supprimé de la base) :
```json
{ "ciphertext": "base64url" }
```

Si déjà lu / expiré / inexistant : `404`.

<h1>⏲️ Cron (optionnel)</h1>

Les secrets expirés sont déjà purgés paresseusement à chaque requête. Pour purger même en l'absence de trafic :

```cron
0 * * * * sqlite3 /path/to/data/seecrets.sqlite "DELETE FROM seecrets WHERE expires_at < strftime('%s','now');"
```

<h1>🛡️ Modèle de menace</h1>

| Scénario | Résultat |
|---|---|
| Serveur compromis (lecture BDD seule) | ✅ Aucun secret déchiffrable — la clé n'y est jamais |
| Fuite du fichier `seecrets.sqlite` | ✅ Que des ciphertexts AES-GCM 256, **incassables** sans la clé |
| Logs serveur exposés | ✅ Les fragments `#` ne sont pas loggés (jamais transmis HTTP) |
| IP loggées dans le rate-limit | ✅ Stockées en hash SHA-256 avec sel quotidien |
| Lecteur légitime consulte le lien | ✅ Secret détruit après lecture (transaction atomique SQLite) |
| Spam de création / brute-force ID | ✅ Rate-limit 20 POST + 60 GET par minute par IP |
| Saturation disque | ✅ Plafond global de 50 000 secrets (`MAX_TOTAL_SECRETS`) |
| Aperçu de lien par bots messagerie | ✅ Gate anti-robot avant fetch |
| CSRF cross-origin form POST | ✅ Refus si `Content-Type ≠ application/json` |
| URL avec clé reste dans l'historique | ✅ `history.replaceState` après lecture réussie |
| Clickjacking via iframe | ✅ `X-Frame-Options: DENY` + CSP `frame-ancestors 'none'` |
| Injection XSS via ciphertext malveillant | ✅ Validation regex `[A-Za-z0-9_-]+`, CSP stricte, `textContent` |
| URL complète interceptée avant lecture | ⚠️ L'attaquant peut lire — mais consomme la 1 vue |
| Force brute sur mot de passe | ⚠️ Mitigée par PBKDF2 **600 000** itérations SHA-256 |
| MITM sans HTTPS | ⚠️ **Activez HTTPS en production** (voir `.htaccess`) |

<h1>🔍 Audit de sécurité</h1>

Cette version a été auditée. Mesures appliquées :

**Cryptographie**
- AES-GCM 256 bits côté client (chiffrement authentifié)
- IV 12 octets random unique par secret
- PBKDF2 SHA-256 avec **600 000 itérations** (OWASP 2023)
- Clés générées via `crypto.subtle.generateKey` (CSPRNG natif)

**API PHP**
- Toutes les requêtes en *prepared statements* PDO (zéro SQL injection)
- Validation stricte des entrées (regex `[A-Za-z0-9_-]+`, bornes de taille)
- `Content-Type: application/json` obligatoire sur POST (mitigation CSRF cross-origin)
- Rate-limit par IP hashée (SHA-256 + sel quotidien) — 20 POST / 60 GET par minute
- Cap de 50 000 secrets max (DoS disque)
- Messages d'erreur génériques, exceptions loggées via `error_log` uniquement
- Transaction SQLite `BEGIN IMMEDIATE` pour la lecture-puis-destruction atomique

**Headers HTTP**
- `Content-Security-Policy` stricte (script-src 'self', frame-ancestors 'none')
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: interest-cohort=(), camera=(), microphone=(), geolocation=()`
- `Cache-Control: no-store` sur l'API

**Apache `.htaccess`**
- Bloque l'accès aux fichiers cachés (`.git`, `.env`, etc.)
- Bloque `.sqlite`, `.log`, `.bak`, `.md`
- Désactive le listing de répertoire
- HSTS et redirection HTTPS en commentaire (à activer en prod)

**Côté client**
- `textContent` partout (jamais `innerHTML`) → pas de XSS via secret déchiffré
- `escapeHtml` sur les URL injectées dans SweetAlert
- `history.replaceState` après lecture → la clé disparaît de l'historique
- Gate anti-bot avant déchiffrement

<h1>🧪 Limites vs la version hébergée</h1>

Cette version est **volontairement minimaliste**. Elle n'inclut **pas** :

- Upload de fichiers (uniquement du texte)
- Comptes utilisateurs et historique
- Statistiques d'accès (date, IP, navigateur, pays)
- Liens à `N` vues configurables (uniquement 1 vue ici)
- Générateur de QR Codes Wi-Fi
- Générateur de mots de passe
- Extensions Thunderbird / navigateur
- API d'authentification avec clés

Pour ces fonctionnalités, utilisez la version SaaS : **[seecret.it](https://seecret.it)**.

<h1>🧭 Liens utiles</h1>

- 🌐 Service hébergé : <https://seecret.it>
- 📄 CGV : <https://seecret.it/fr/cgv>
- 🔐 Politique de confidentialité : <https://seecret.it/fr/privacy-policy>
- 📰 Blog : <https://seecret.it/blog>
- 🔧 Générateur QR Wi-Fi : <https://seecret.it/fr/qrcode_wifi>
- 🔑 Générateur de mots de passe : <https://seecret.it/fr/password-generator>

<h1>🏷️ Mots-clés</h1>

`security` · `password-sharing` · `encrypted-links` · `privacy` · `cybersecurity` · `zero-knowledge` · `self-hosted` · `aes-gcm` · `php` · `sqlite` · `vanilla-javascript` · `open-source`

<h1>🧑‍💻 À propos</h1>

Développé pour simplifier le partage de données sensibles et améliorer les pratiques de sécurité au quotidien.
Seecret.it évolue constamment — de nouvelles intégrations et fonctionnalités arrivent régulièrement.

PRs et issues bienvenues ! 🚀
