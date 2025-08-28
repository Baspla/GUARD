# GUARD

**GUARD** ist ein leichtgewichtiges Single-Sign-On (SSO) System für eigene Projekte. Es bietet eine einfache Authentifizierung und Benutzerverwaltung für verschiedene Webanwendungen.

---

## Features

- Benutzerregistrierung und Login
- Passwort-, Nutzername- und Displayname-Änderung
- Session-Management mit Redis
- Token-basierte Authentifizierung für externe Plattformen
- Einfache Integration über Redirect und Code-Parameter
- Fehlerseiten und Statusmeldungen
- Moderne UI mit Pug und Bootstrap

## Endpunkte

| Route                | Beschreibung                                       |
|----------------------|----------------------------------------------------|
| `/login`             | Login-Seite, unterstützt `redirect_uri` und `state`|
| `/register`          | Registrierung eines neuen Benutzers                |
| `/logout`            | Abmelden                                           |
| `/dashboard`         | Benutzer-Dashboard                                 |
| `/token?code=...`    | Token-Validierung und Benutzerdaten abrufen        |
| `/info?uuid=...`     | Benutzerinformationen per UUID abrufen             |
| `/admin`             | Admin-Panel für Benutzerverwaltung                 |

## Umgebungsvariablen

Folgende Umgebungsvariablen werden von GUARD verwendet:

| Variable         | Beschreibung                                      |
|------------------|---------------------------------------------------|
| `SECRET`         | Session-Secret für express-session                |
| `REDIS_HOST`     | Hostname/IP des Redis-Servers                     |
| `REDIS_PORT`     | Port des Redis-Servers                            |
| `REGISTER_SECRET`| Secret für die Registrierung                      |
| `JWT_SECRET`     | Secret für die Signierung der JSON Web Tokens     |
| `ADMIN_UUID`     | UUID des Admin-Benutzers für die Admin-Seite      |

## Integration

Um GUARD als SSO zu nutzen, leite den Benutzer auf die Login-Seite:

```text
https://guard.example.com/login?redirect_uri=https://app.example.com/receiver&state=optionalState
```

Nach erfolgreichem Login wird der Benutzer auf die angegebene `redirect_uri` zurückgeleitet:

```text
https://app.example.com/receiver?code=TOKEN&state=optionalState
```

Die App kann dann die Benutzerdaten mit dem Token abfragen:

```text
GET https://guard.example.com/token?code=TOKEN
```

Antwort:

```json
{
  "uuid": "...",
  "displayname": "..."
}
```

## Sicherheit & Hinweise

- GUARD ist ein privates Projekt und nicht für produktive Umgebungen gedacht.
- Keine Garantie für Sicherheit oder Stabilität.
- Kein OpenID-, OAuth-, SAML-, LDAP- oder CAS-Provider.

## Roadmap

- Webhooks für User-Events
- Admin-Panel
- Multi-Faktor-Authentifizierung
- API für Benutzerverwaltung

---

**Made with ❤️ by Baspla**