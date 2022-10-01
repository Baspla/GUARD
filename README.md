# GUARD
GUARD is a custom SSO platform for various upcoming personal projects

### Deutsch
GUARD ist eine selbstentwickelte SSO-Plattform für verschiedene zukünftige Projekte

## Disclaimer
This project is a personal project and is not intended for production use.
I can not make any guarantees about the security of this project. Use at your own risk.
This project does not represent my employer in any way, shape or form.

## Was ist GUARD?
GUARD steht für den "Gotteslachs Universal Authentfikations- und Registrierungs-Dienst".
GUARD ist ein SSO-System, welches es ermöglicht, sich auf verschiedenen Plattformen mit einem einzigen Account anzumelden.

## Warum GUARD?
GUARD wurde entwickelt, um die Anmeldung auf verschiedenen Plattformen zu vereinfachen.
Zudem soll GUARD die Möglichkeit bieten, sich auf verschiedenen Plattformen mit einem einzigen Account anzumelden.

## Wie integriere ich GUARD in meine Plattform?
Um einen Token von GUARD anzufordern, muss der Benutzer auf die GUARD-Loginseite weitergeleitet werden.
Dort kann er sich mit seinen Zugangsdaten anmelden und erhält anschließend einen Token.
Mit diesem Token wird der Benutzer auf die Plattform zurückgeleitet, wo er sich mit dem Token authentifizieren kann.

Die Seite auf die der Benutzer zurückgeleitet wird, muss im returnURL-Parameter angegeben werden.
Auf dieser Seite muss der Token in der URL als GUARDTOKEN-Parameter empfangen werden.
Der Token kann dann an die GUARD-API geschickt werden,
um die Gültigkeit zu überprüfen und Benutzername so wie Displayname zu erhalten.
### Beispiel
`https://guard.example.com/login?returnURL=https://app.example.com/reciever` führt zu einer Anmeldeseite die,
nachdem der Benutzer sich angemeldet hat, den Benutzer auf `https://app.example.com/reciever?GUARDTOKEN=token` zurückleitet.
Die App kann dann die Benutzerdaten mit dem Token auf `https://guard.example.com/sso` abfragen.

## Wie kann ich GUARD selbst hosten?
GUARD ist als Docker-Container verfügbar.
`baspla/guard:latest`

Ich verwende Docker-Compose, um GUARD zu hosten.
```yaml
version: '3.3'
services:
  redis:
    image: redis
    restart: unless-stopped
    volumes:
      - .../guardsso:/data
    expose:
        - 6379
    networks:
      backend:
        aliases:
          - redis

  app:
    environment:
      - SECRET=...
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - VIRTUAL_HOST=guard.example.com
      - LETSENCRYPT_HOST=guard.example.com
      - LETSENCRYPT_EMAIL=email@example.com
    restart: unless-stopped
    networks:
      - backend
      - proxy
    depends_on:
      - redis
    image: baspla/guard
networks:
  proxy:
    external: true
  backend:
```

## Was ist GUARD nicht?
GUARD ist kein OpenID-, OAuth-, SAML-, LDAP- oder CAS-Provider

## Was ist GUARD in Zukunft?
GUARD ist vom Funktionsumfang quasi fertig. Komplexere Features sollten auf Plattformen entstehen, sie GUARD als SSO-Provider nutzen.