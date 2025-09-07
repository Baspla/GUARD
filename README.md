# GUARD

**GUARD** ist ein leichtgewichtiges Single-Sign-On (SSO) System für eigene Projekte. Es bietet eine einfache Authentifizierung und Benutzerverwaltung für verschiedene Webanwendungen.

---

## Features

- Benutzerregistrierung und Login
- Login mit mehreren Passkeys
- Passwort-, Nutzername- und Displayname-Änderung
- Verwaltung von Passkeys
- Session-Management mit Redis
- Token-basierte Authentifizierung für externe Plattformen
- Einfache Integration über Redirect und Code-Parameter
- Fehlerseiten und Statusmeldungen
- Moderne UI mit Pug und Bootstrap

## Endpunkte

| Route                              | Beschreibung                                       |
|------------------------------------|----------------------------------------------------|
| `/login`                           | Login-Seite, unterstützt `redirect_uri` und `state`|
| `/register`                        | Registrierung eines neuen Benutzers                |
| `/logout`                          | Abmelden                                           |
| `/dashboard`                       | Benutzer-Dashboard                                 |
| `/token?code=...`                  | Token-Validierung und Benutzerdaten abrufen        |
| `/info?uuid=...`                   | Benutzerinformationen per UUID abrufen             |
| `/admin`                           | Admin-Panel für Benutzerverwaltung                 |
| `/generate-registration-options`   | Registrierung-Optionen generieren                  |
| `/generate-authentication-options` | Authentifizierungs-Optionen generieren             |
| `/verify-registration`             | Registrierung verifizieren                         |
| `/verify-authentication`           | Authentifizierung verifizieren                     |
| `/auth_request`                    | Interne Route für Proxy-Flow (SSO-Check)           |
| `/`                                | Root-Route, leitet zu Login oder Dashboard weiter  |

## Umgebungsvariablen

Folgende Umgebungsvariablen werden von GUARD verwendet:

| Variable            | Beschreibung                                               |
|---------------------|------------------------------------------------------------|
| `SECRET`            | Session-Secret für express-session                         |
| `REDIS_HOST`        | Hostname/IP des Redis-Servers                              |
| `REDIS_PORT`        | Port des Redis-Servers                                     |
| `REGISTER_SECRET`   | Secret für die Registrierung                               |
| `JWT_SECRET`        | Secret für die Signierung der JSON Web Tokens              |
| `ADMIN_UUID`        | UUID des Admin-Benutzers für die Admin-Seite               |
| `RP_ID`             | ID des Relying Parties (guard.example.com)                 |
| `REGISTER_DISABLED` | Wenn auf `true` gesetzt, ist die Registrierung deaktiviert |
| `COOKIE_DOMAIN`     | Domain für die Session-Cookies (z.B. `.example.com`)       |

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

### GUARD als Proxy-Flow

Beispiel Konfiguration für Nginx:

```nginx
# Increase buffer size for large headers (only if you encounter large upstream headers)
proxy_buffers 8 16k;        # optional, only if needed for big headers
proxy_buffer_size 32k;      # optional, only if needed for big headers

# Protect the whole site
location / {
    # application upstream (fill in your upstream; in NPM this is handled by proxy_pass to your container)
    proxy_pass          $forward_scheme://$server:$port;  # placeholder used by NPM Advanced config

    # Enforce SSO via internal subrequest
    auth_request        /auth;                             # subrequest to internal /auth
    error_page          401 = @sso_signin;                 # handle 401 by redirecting to SSO

    # Optionally forward user attributes from SSO (if SSO returns headers)
    auth_request_set    $sso_user   $upstream_http_x_user; # example header from SSO
    proxy_set_header    X-User      $sso_user;             # pass to app
}

# Internal auth subrequest endpoint
location = /auth {
    internal;                                               # only subrequests can hit this
    proxy_pass              http://guard/auth_request;  # your SSO check URL

    proxy_pass_request_body off;                            # discard body for subrequest
    proxy_set_header        Content-Length "";              # required with body off

    # Send original request context to SSO
    proxy_set_header        X-Original-URI   $request_uri;  # original path+query
    proxy_set_header        Host             $host;         # preserve host if SSO needs it
    proxy_set_header        X-Original-Method $request_method; # optional, if your SSO uses it

    # Forward cookies if the SSO relies on session cookies from the protected domain
    proxy_set_header        Cookie          $http_cookie;   # forward inbound cookies to SSO
}

# Sign-in redirect on 401 from SSO
location @sso_signin {
    internal;
    # Redirect to your SSO login/start page with return-to; adjust to your SSO’s expected param
    return 302 https://guard.example.com/login?proxy=true&redirect_uri=$scheme://$http_host$request_uri;  # preserve full URL
}
```

## Sicherheit & Hinweise

- GUARD ist ein privates Projekt und nicht für produktive Umgebungen gedacht.
- Keine Garantie für Sicherheit oder Stabilität.
- Kein OpenID-, OAuth-, SAML-, LDAP- oder CAS-Provider.

---

**Made with ❤️ by Baspla**