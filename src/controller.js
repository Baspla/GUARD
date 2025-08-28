import { getAllUsers } from "./db.js";
import fs from "fs";
import path from "path";

function log(message) {
    const logPath = path.resolve("./logs/app.log");
    const timestamp = new Date().toISOString();
    fs.mkdirSync(path.dirname(logPath), { recursive: true });
    fs.appendFileSync(logPath, `[${timestamp}] ${message}\n`);
    console.log(`[${timestamp}] ${message}`);
}
export async function admin(req, res) {
    log("Admin-Panel Zugriff versucht von UUID: " + req.session.uuid);
    const adminUuid = process.env.ADMIN_UUID;
    if (!req.session.uuid || req.session.uuid !== adminUuid) {
        log("Admin-Panel Zugriff verweigert für UUID: " + req.session.uuid);
        return res.status(403).render('error', {error: 403, message: "Zugriff verweigert"});
    }
    const users = await getAllUsers();
    log("Admin-Panel Zugriff gewährt. Nutzer geladen: " + users.length);
    res.render('admin', {users, title: "Admin"});
}

export async function adminPasskeysView(req, res) {
    log(`AdminPasskeys-View aufgerufen von UUID: ${req.session.uuid}`);
    const adminUuid = process.env.ADMIN_UUID;
    if (!req.session.uuid || req.session.uuid !== adminUuid) {
        log(`AdminPasskeys Zugriff verweigert für UUID: ${req.session.uuid}`);
        return res.status(403).render('error', {error: 403, message: "Zugriff verweigert"});
    }
    const { uuid } = req.params;
    if (!uuid) {
        log('AdminPasskeys Fehler: uuid fehlt in URL');
        return res.redirect('/admin');
    }
    try {
        const creds = await getCredentials(uuid);
        const displayname = await getDisplayname(uuid);
        const username = await getUsername(uuid);
        res.render('adminPasskeys', { uuid, displayname, username, credentials: creds, title: `Passkeys von ${username || uuid}` });
    } catch (err) {
        log(`AdminPasskeys Fehler: ${err}`);
        return res.redirect('/admin');
    }
}

export async function doAdminDeletePasskey(req, res) {
    log(`AdminDeletePasskey aufgerufen von UUID: ${req.session.uuid}`);
    const adminUuid = process.env.ADMIN_UUID;
    if (!req.session.uuid || req.session.uuid !== adminUuid) {
        log(`AdminDeletePasskey Zugriff verweigert für UUID: ${req.session.uuid}`);
        return res.status(403).render('error', {error: 403, message: "Zugriff verweigert"});
    }
    const { uuid, id } = req.params;
    if (!uuid || !id) {
        log('AdminDeletePasskey Fehler: fehlende Parameter');
        return res.redirect('/admin');
    }
    try {
        await deleteCredential(uuid, id);
        log(`AdminDeletePasskey erfolgreich: ${id} von ${uuid}`);
        return res.redirect(`/admin/passkeys/${encodeURIComponent(uuid)}`);
    } catch (err) {
        log(`AdminDeletePasskey Fehler: ${err}`);
        return res.redirect('/admin');
    }
}

// Admin: Passwort zurücksetzen (Formular)
export function adminPasswordResetView(req, res) {
    const { username } = req.params;
    log(`AdminPasswordReset-View aufgerufen von UUID: ${req.session.uuid} für username: ${username}`);
    const adminUuid = process.env.ADMIN_UUID;
    if (!req.session.uuid || req.session.uuid !== adminUuid) {
        log(`AdminPasswordReset Zugriff verweigert für UUID: ${req.session.uuid}`);
        return res.status(403).render('error', {error: 403, message: "Zugriff verweigert"});
    }
    if (!username) {
        log('AdminPasswordReset Fehler: username fehlt in URL');
        return res.redirect('/admin?error=13');
    }
    // Zeige Formular zum Setzen eines neuen Passworts für den Nutzer
    res.render('adminPasswordReset', {username: username, title: `Passwort zurücksetzen: ${username}`});
}

// Admin: Passwort setzen (Formular-Submit)
export function doAdminPasswordReset(req, res) {
    const { username } = req.params;
    const { password, passwordRepeat } = req.body;
    log(`AdminPasswordReset Aktion von UUID: ${req.session.uuid} für username: ${username}`);
    const adminUuid = process.env.ADMIN_UUID;
    if (!req.session.uuid || req.session.uuid !== adminUuid) {
        log(`AdminPasswordReset Zugriff verweigert für UUID: ${req.session.uuid}`);
        return res.status(403).render('error', {error: 403, message: "Zugriff verweigert"});
    }
    if (!username) {
        log('AdminPasswordReset Fehler: username fehlt in URL');
        return res.redirect('/admin?error=13');
    }
    if (password == null || passwordRepeat == null) {
        log('AdminPasswordReset Fehler: Felder fehlen');
        return res.redirect(`/admin/passwordreset/${encodeURIComponent(username)}?error=9`);
    }
    if (!isPasswordValid(password)) {
        log('AdminPasswordReset Fehler: Ungültiges Passwort');
        return res.redirect(`/admin/passwordreset/${encodeURIComponent(username)}?error=10`);
    }
    if (password !== passwordRepeat) {
        log('AdminPasswordReset Fehler: Passwörter stimmen nicht überein');
        return res.redirect(`/admin/passwordreset/${encodeURIComponent(username)}?error=5`);
    }
    // Finde UUID und setze Passwort
    getUUIDByUsername(username).then((uuid) => {
        if (uuid == null) {
            log(`AdminPasswordReset Fehler: Nutzer ${username} nicht gefunden`);
            return res.redirect('/admin?error=2');
        }
        setPassword(uuid, password).then(() => {
            log(`AdminPasswordReset erfolgreich: Passwort für ${username} (UUID: ${uuid}) geändert`);
            return res.redirect('/admin');
        }).catch((err) => {
            log(`AdminPasswordReset Fehler beim Setzen des Passworts: ${err}`);
            return res.redirect('/admin?error=14');
        });
    }).catch((err) => {
        log(`AdminPasswordReset Fehler beim Laden der UUID: ${err}`);
        return res.redirect('/admin?error=14');
    });
}
// noinspection SpellCheckingInspection

import {v4 as generateuuid} from "uuid";
import {
    checkPassword,
    getDisplayname, getUsername, getUUIDByUsername,
    isUsernameAvailable,
    setDisplayname, setPassword, setUsername,
    storeUser,
    updateLastLogin
} from "./db.js";
import {
    addCredential,
    getCredentials,
    getCredential,
    deleteCredential,
    updateSignCount
} from "./db.js";
import {isDisplaynameValid, isPasswordValid, isUsernameValid} from "./validator.js";
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import base64url from 'base64url';

export function passkeysRegisterView(req, res) {
    if (!isLoggedIn(req)) return res.redirect('/');
    res.render('passkeys_register', { title: 'Passkey registrieren' });
}

export function login(req, res) {
    const {redirect_uri, error, state} = req.query;
    log(`Login-View aufgerufen. Session UUID: ${req.session.uuid}, redirect_uri: ${redirect_uri}, error: ${error}, state: ${state}`);
    if (isLoggedIn(req)) {
        if (redirect_uri == null) {
            log("Nutzer ist bereits eingeloggt ohne ServiceURL.");
            return res.redirect("/");
        } else {
            let hostname;
            try {
                const url = new URL(redirect_uri);
                hostname = url.hostname;
            } catch (e) {
                log("Ungültige redirect_uri beim Login: " + redirect_uri);
                let err = new Error("Die angegebene redirect_uri ist ungültig.");
                err.status = 400;
                throw err;
            }
            return getUsername(req.session.uuid).then(username => {
                log(`Prompt-View für Nutzer: ${username}, redirect_uri: ${redirect_uri}`);
                return res.render('prompt', {
                    username: username,
                    redirect_uri: redirect_uri,
                    hostname: hostname,
                    error: error,
                    state: state,
                    title: "Bestätigen"
                });
            });
        }
    } else {
        if (redirect_uri == null) {
            log("Login-View für nicht eingeloggten Nutzer ohne ServiceURL.");
            return res.render("login", {registerSuffix: "", error: error, title: "Anmelden", state: state});
        } else {
            let hostname;
            try {
                const url = new URL(redirect_uri);
                hostname = url.hostname;
            } catch (e) {
                log("Ungültige redirect_uri beim Login: " + redirect_uri);
                let err = new Error("Die angegebene redirect_uri ist ungültig.");
                err.status = 400;
                throw err;
            }
            log(`Login-View für nicht eingeloggten Nutzer mit ServiceURL: ${redirect_uri}`);
            return res.render("login", {
                registerSuffix: "?redirect_uri=" + redirect_uri + (state ? "&state=" + encodeURIComponent(state) : ""),
                error: error,
                hostname: hostname,
                title: "Anmelden",
                state: state
            });
        }
    }

}

export function logout(req, res) {
    const {redirect_uri, state} = req.query;
    log(`Logout aufgerufen. Session UUID: ${req.session.uuid}, redirect_uri: ${redirect_uri}, state: ${state}`);
    req.session.destroy();
    if (redirect_uri != null) {
        let suffix = '/login?redirect_uri=' + encodeURIComponent(redirect_uri);
        if (state) suffix += '&state=' + encodeURIComponent(state);
        log("Logout mit redirect_uri. Weiterleitung zu: " + suffix);
        return res.redirect(suffix);
    }
    log("Logout ohne redirect_uri. Zeige Logout-View.");
    res.render('logout', {title: "Abgemeldet"});
}


export function registerUser(req, res) {
    log("Register-View aufgerufen. Session UUID: " + req.session.uuid);
    if (isLoggedIn(req)) {
        log("Nutzer ist bereits eingeloggt. Weiterleitung zu Startseite.");
        return res.redirect('/');
    }
    const {error, state, redirect_uri} = req.query;
    log(`Register-View für nicht eingeloggten Nutzer. error: ${error}, state: ${state}, redirect_uri: ${redirect_uri}`);
    return res.render("register", {error: error, title: "Registrieren", state: state, redirect_uri: redirect_uri});
}

export function doRegisterUser(req, res, next) {
    const {username, password, passwordRepeat, displayname, secret} = req.body;
    const {redirect_uri, state} = req.query;
    log(`Registrierung gestartet für Nutzer: ${username}, displayname: ${displayname}`);
    let suffix = "";
    if (redirect_uri != null) {
        suffix = "&redirect_uri=" + encodeURIComponent(redirect_uri);
    }
    if (state) {
        suffix += "&state=" + encodeURIComponent(state);
    }
    if (secret !== process.env.REGISTER_SECRET) {
        log("Registrierung fehlgeschlagen: falsches Secret.");
        return res.redirect('/register?error=12' + suffix);
    }
    if (password !== passwordRepeat) {
        log("Registrierung fehlgeschlagen: Passwörter stimmen nicht überein.");
        return res.redirect('/register?error=5' + suffix);
    }
    if (!isUsernameValid(username)) {
        log("Registrierung fehlgeschlagen: Ungültiger Nutzername.");
        return res.redirect('/register?error=7' + suffix);
    }
    if (!isPasswordValid(password)) {
        log("Registrierung fehlgeschlagen: Ungültiges Passwort.");
        return res.redirect('/register?error=10' + suffix);
    }
    if (!isDisplaynameValid(displayname)) {
        log("Registrierung fehlgeschlagen: Ungültiger Displayname.");
        return res.redirect('/register?error=4' + suffix);
    }
    isUsernameAvailable(username).then((exists) => {
        if (exists) {
            log("Registrierung fehlgeschlagen: Nutzername bereits vergeben.");
            return res.redirect('/register?error=6' + suffix);
        } else {
            let uuid = generateuuid();
            storeUser(uuid, username, password, displayname).then(() => {
                log(`Nutzer registriert: ${username}, UUID: ${uuid}, Displayname: ${displayname}`);
                req.session.uuid = uuid;
                return res.redirect('/login' + suffix);
            }).catch((err) => {
                log("Fehler bei Registrierung: " + err);
                next(err);
            });
        }
    }).catch((err) => {
        log("Fehler bei Registrierung: " + err);
        next(err);
    });
}

function registerTokenAndRedirect(req, res, redirect_uri, state) {
    log(`Token-Registrierung und Redirect für UUID: ${req.session.uuid}, redirect_uri: ${redirect_uri}, state: ${state}`);
    // JWT mit uuid als Payload
    const token = signToken({ uuid: req.session.uuid });
    var url = new URL(redirect_uri);
    if (typeof state !== 'undefined') url.searchParams.append('state', state);
    url.searchParams.append('code', token);
    log(`Redirect mit Token: ${token} zu URL: ${url}`);
    res.redirect(url);
}

export function token(req, res) {
    const {code} = req.query;
    log(`Token-Endpoint aufgerufen mit code: ${code}`);
    if (code == null) {
        log("Token-Fehler: code fehlt.");
        return res.status(400).json({error: "code fehlt.", code: 400});
    }
    const payload = verifyToken(code);
    if (!payload || !payload.uuid) {
        log("Token-Fehler: code ungültig.");
        return res.status(400).json({error: "code ist ungültig.", code: 400});
    }
    getDisplayname(payload.uuid).then((displayname) => {
        if (displayname == null) {
            log("Token-Fehler: UUID ungültig.");
            return res.status(400).json({error: "UUID ist ungültig.", code: 400});
        }
        log(`Token erfolgreich: UUID: ${payload.uuid}, Displayname: ${displayname}`);
        res.status(200).json({uuid: payload.uuid, displayname: displayname});
    });
}

export function getInformation(req, res) {
    const {uuid} = req.query;
    log(`getInformation aufgerufen mit UUID: ${uuid}`);
    if (uuid == null) {
        log("getInformation Fehler: UUID fehlt.");
        return res.status(400).json({error: "UUID fehlt.", code: 400});
    }
    getDisplayname(uuid).then((displayname) => {
        if (displayname == null) {
            log("getInformation Fehler: UUID ungültig.");
            return res.status(400).json({error: "UUID ist ungültig.", code: 400});
        }
        log(`getInformation erfolgreich: UUID: ${uuid}, Displayname: ${displayname}`);
        res.status(200).json({uuid: uuid, displayname: displayname});
    });
}

function isLoggedIn(req) {
    return req.session.uuid != null;
}

// WebAuthn / Passkey helpers
const rpName = process.env.RP_NAME || 'GUARD SSO';
const rpID = process.env.RP_ID || undefined; // use host if undefined
const origin = process.env.ORIGIN || undefined; // must be set in env for verification

export function passkeysRegisterOptions(req, res) {
    if (!isLoggedIn(req)) return res.status(403).send('Forbidden');
    const userHandle = req.session.uuid;
    const usernamePromise = getUsername(userHandle);
    usernamePromise.then(username => {
        const opts = generateRegistrationOptions({
            rpName: rpName,
            rpID: rpID,
            userID: userHandle,
            userName: username || userHandle,
            attestationType: 'none',
            authenticatorSelection: { userVerification: 'preferred' },
            // excludeCredentials should be built from existing credentials
            // We'll fill it below after reading creds
        });
        // store challenge in session
        req.session.currentChallenge = opts.challenge;
        // attach empty allowCredentials for client; server may fill exclude on client side
        res.json(opts);
    }).catch(err => {
        log('passkeysRegisterOptions Fehler: ' + err);
        res.status(500).send('DB error');
    });
}

export async function passkeysVerifyRegistration(req, res) {
    if (!isLoggedIn(req)) return res.status(403).send('Forbidden');
    const body = req.body;
    const expectedChallenge = req.session.currentChallenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'challenge missing' });
    let verification;
    try {
        verification = await verifyRegistrationResponse({
            credential: body,
            expectedChallenge: expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
        });
    } catch (e) {
        log('verifyRegistration error: ' + e);
        return res.status(400).json({ error: 'verification failed' });
    }
    const { verified, registrationInfo } = verification;
    if (!verified || !registrationInfo) {
        return res.status(400).json({ error: 'not verified' });
    }
    const credID = registrationInfo.credentialID.toString('base64url');
    const publicKey = registrationInfo.credentialPublicKey.toString('base64');
    const signCount = registrationInfo.counter || 0;
    const transports = body.transports || [];
    const name = body.name || null;
    await addCredential(req.session.uuid, credID, { id: credID, publicKey: publicKey, signCount: String(signCount), transports: JSON.stringify(transports), name: name, lastUsed: String(Date.now()) });
    delete req.session.currentChallenge;
    res.json({ ok: true });
}

export async function passkeysAuthOptions(req, res) {
    // For login: either user is known (session) or username provided in query/body
    let username = null;
    let userUUID = null;
    if (isLoggedIn(req)) {
        userUUID = req.session.uuid;
    } else if (req.query.username) {
        userUUID = await getUUIDByUsername(req.query.username);
        if (!userUUID) return res.status(400).json({ error: 'unknown user' });
    } else {
        return res.status(400).json({ error: 'no user provided' });
    }
    const creds = await getCredentials(userUUID);
    const allowCredentials = creds.map(c => ({ id: base64url.toBuffer(c.id), type: 'public-key' }));
    const opts = generateAuthenticationOptions({
        timeout: 60000,
        allowCredentials: allowCredentials,
        userVerification: 'preferred',
        rpID: rpID
    });
    req.session.currentChallenge = opts.challenge;
    // store which user this challenge is for if not logged in
    req.session.currentChallengeUser = userUUID;
    res.json(opts);
}

export async function passkeysVerifyAuth(req, res) {
    const body = req.body;
    const expectedChallenge = req.session.currentChallenge;
    const userUUID = req.session.currentChallengeUser || req.session.uuid;
    if (!expectedChallenge || !userUUID) return res.status(400).json({ error: 'missing challenge or user' });
    const cred = await getCredential(userUUID, body.id);
    if (!cred) return res.status(400).json({ error: 'unknown credential' });
    let verification;
    try {
        verification = await verifyAuthenticationResponse({
            credential: body,
            expectedChallenge: expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            authenticator: {
                credentialPublicKey: Buffer.from(cred.publicKey, 'base64'),
                credentialID: base64url.toBuffer(cred.id),
                counter: cred.signCount || 0,
            }
        });
    } catch (e) {
        log('verifyAuthentication error: ' + e);
        return res.status(400).json({ error: 'verification failed' });
    }
    const { verified, authenticationInfo } = verification;
    if (!verified) return res.status(400).json({ error: 'not verified' });
    // check counter
    if (authenticationInfo && typeof authenticationInfo.newCounter === 'number') {
        if (authenticationInfo.newCounter <= (cred.signCount || 0)) {
            log(`Potential cloned credential for user ${userUUID} cred ${cred.id}`);
            // Do not authenticate, but allow admin investigation. For now, reject.
            return res.status(400).json({ error: 'counter regression' });
        }
        await updateSignCount(userUUID, cred.id, authenticationInfo.newCounter);
    }
    // Authentication successful -> set session
    req.session.uuid = userUUID;
    updateLastLogin(userUUID);
    delete req.session.currentChallenge;
    delete req.session.currentChallengeUser;
    res.json({ ok: true });
}

export async function passkeysListView(req, res) {
    if (!isLoggedIn(req)) return res.redirect('/');
    const creds = await getCredentials(req.session.uuid);
    res.render('passkeys', { credentials: creds, title: 'Passkeys verwalten' });
}

export async function passkeysDelete(req, res) {
    if (!isLoggedIn(req)) return res.status(403).send('Forbidden');
    const { id } = req.params;
    if (!id) return res.status(400).send('Missing id');
    await deleteCredential(req.session.uuid, id);
    res.redirect('/passkeys');
}

export function dashboard(req, res) {
    const {redirect_uri, error, state} = req.query;
    log(`Dashboard-View aufgerufen. Session UUID: ${req.session.uuid}, redirect_uri: ${redirect_uri}, error: ${error}, state: ${state}`);
    if (!isLoggedIn(req)) {
        let suffix = '/login';
        if (redirect_uri) {
            suffix += '?redirect_uri=' + encodeURIComponent(redirect_uri);
            if (state) suffix += '&state=' + encodeURIComponent(state);
        }
        log("Dashboard-View: Nutzer nicht eingeloggt. Weiterleitung zu: " + suffix);
        return res.redirect(suffix);
    }
    let uname = getUsername(req.session.uuid);
    let dname = getDisplayname(req.session.uuid);
    Promise.all([uname, dname]).then((values) => {
        log(`Dashboard-View für Nutzer: ${values[0]}, Displayname: ${values[1]}`);
        res.render('dashboard', {username: values[0], displayname: values[1], error: error, title: "Dashboard", state: state, redirect_uri: redirect_uri});
    });
}

export function displaynamechange(req, res) {
    log("Displaynamechange-View aufgerufen. Session UUID: " + req.session.uuid);
    if (!isLoggedIn(req)) {
        log("Displaynamechange: Nutzer nicht eingeloggt. Weiterleitung zu Startseite.");
        return res.redirect('/');
    }
    let uname = getUsername(req.session.uuid);
    let dname = getDisplayname(req.session.uuid);
    Promise.all([uname, dname]).then((values) => {
        log(`Displaynamechange-View für Nutzer: ${values[0]}, Displayname: ${values[1]}`);
        res.render('changeDisplay', {username: values[0], displayname: values[1],title: "Displayname ändern"});
    });
}

export function usernamechange(req, res) {
    log("Usernamechange-View aufgerufen. Session UUID: " + req.session.uuid);
    if (!isLoggedIn(req)) {
        log("Usernamechange: Nutzer nicht eingeloggt. Weiterleitung zu Startseite.");
        return res.redirect('/');
    }
    getUsername(req.session.uuid).then((username) => {
        log(`Usernamechange-View für Nutzer: ${username}`);
        res.render('changeUsername', {username: username,title: "Nutzername ändern"});
    });
}

export function passwordchange(req, res) {
    log("Passwordchange-View aufgerufen. Session UUID: " + req.session.uuid);
    if (!isLoggedIn(req)) {
        log("Passwordchange: Nutzer nicht eingeloggt. Weiterleitung zu Startseite.");
        return res.redirect('/');
    }
    getUsername(req.session.uuid).then((username) => {
        log(`Passwordchange-View für Nutzer: ${username}`);
        res.render('changePassword', {username: username,title: "Passwort ändern"});
    });
}



export function doDisplaynamechange(req, res) {
    log("doDisplaynamechange aufgerufen. Session UUID: " + req.session.uuid);
    if (!isLoggedIn(req)) {
        log("doDisplaynamechange: Nutzer nicht eingeloggt. Weiterleitung zu Startseite.");
        return res.redirect('/');
    }
    const {displayname} = req.body;
    if (displayname == null) {
        log("doDisplaynamechange Fehler: Displayname fehlt.");
        return res.redirect('/displaynamechange?error=3');
    }
    if (!isDisplaynameValid(displayname)) {
        log("doDisplaynamechange Fehler: Ungültiger Displayname.");
        return res.redirect('/displaynamechange?error=4');
    }
    setDisplayname(req.session.uuid, displayname).then(() => {
        log(`Displayname geändert für UUID: ${req.session.uuid} zu: ${displayname}`);
        res.redirect('/');
    });
}

export function doUsernamechange(req, res) {
    log("doUsernamechange aufgerufen. Session UUID: " + req.session.uuid);
    if (!isLoggedIn(req)) {
        log("doUsernamechange: Nutzer nicht eingeloggt. Weiterleitung zu Startseite.");
        return res.redirect('/');
    }
    const {username} = req.body;
    if (username == null) {
        log("doUsernamechange Fehler: Nutzername fehlt.");
        return res.redirect('/usernamechange?error=8');
    }
    if (!isUsernameValid(username)) {
        log("doUsernamechange Fehler: Ungültiger Nutzername.");
        return res.redirect('/usernamechange?error=7');
    }
    setUsername(req.session.uuid, username).then(() => {
        log(`Nutzername geändert für UUID: ${req.session.uuid} zu: ${username}`);
        res.redirect('/');
    });
}

export function doPasswordchange(req, res) {
    log("doPasswordchange aufgerufen. Session UUID: " + req.session.uuid);
    if (!isLoggedIn(req)) {
        log("doPasswordchange: Nutzer nicht eingeloggt. Weiterleitung zu Startseite.");
        return res.redirect('/');
    }
    const {password, passwordRepeat, oldPassword} = req.body;
    if (password == null || passwordRepeat == null || oldPassword == null) {
        log("doPasswordchange Fehler: Felder fehlen.");
        return res.redirect('/passwordchange?error=9');
    }
    if (!isPasswordValid(password)) {
        log("doPasswordchange Fehler: Ungültiges Passwort.");
        return res.redirect('/passwordchange?error=10');
    }
    if (password !== passwordRepeat) {
        log("doPasswordchange Fehler: Passwörter stimmen nicht überein.");
        return res.redirect('/?error=5');
    }
    if (!checkPassword(req.session.uuid, oldPassword)) {
        log("doPasswordchange Fehler: Altes Passwort falsch.");
        return res.redirect('/?error=11');
    }
    setPassword(req.session.uuid, password).then(() => {
        log(`Passwort geändert für UUID: ${req.session.uuid}`);
        res.redirect('/');
    });
}


export function doLogin(req, res) {
    const {username, password, confirmed} = req.body;
    const {redirect_uri, state} = req.query;
    log(`doLogin aufgerufen. username: ${username}, confirmed: ${confirmed}, redirect_uri: ${redirect_uri}, state: ${state}`);
    if ((username == null || password == null) && confirmed !== "true") {
        log("doLogin Fehler: Felder fehlen.");
        let suffix = '/login?error=1';
        if (redirect_uri) {
            suffix += '&redirect_uri=' + encodeURIComponent(redirect_uri);
        }
        if (state) {
            suffix += '&state=' + encodeURIComponent(state);
        }
        return res.redirect(suffix);
    }
    if (confirmed === "true") {
        if (isLoggedIn(req)) {
            log("doLogin: Nutzer bestätigt und eingeloggt. Token wird registriert.");
            return registerTokenAndRedirect(req, res, redirect_uri, state);
        } else {
            log("doLogin Fehler: Nutzer nicht eingeloggt bei Bestätigung.");
            let suffix = '/login?error=1';
            if (redirect_uri) {
                suffix += '&redirect_uri=' + encodeURIComponent(redirect_uri);
            }
            if (state) {
                suffix += '&state=' + encodeURIComponent(state);
            }
            return res.redirect(suffix);
        }
    } else {
        getUUIDByUsername(username).then((uuid) => {
            if (uuid == null) {
                log("doLogin Fehler: Nutzername nicht gefunden.");
                let suffix = '/login?error=2';
                if (redirect_uri) {
                    suffix += '&redirect_uri=' + encodeURIComponent(redirect_uri);
                }
                if (state) {
                    suffix += '&state=' + encodeURIComponent(state);
                }
                return res.redirect(suffix);
            }
            checkPassword(uuid, password).then((result) => {
                if (result) {
                    log(`doLogin erfolgreich: Nutzer eingeloggt. UUID: ${uuid}`);
                    req.session.uuid = uuid;
                    updateLastLogin(uuid);
                    if (redirect_uri != null) {
                        return registerTokenAndRedirect(req, res, redirect_uri, state);
                    } else {
                        return res.redirect("/");
                    }
                } else {
                    log("doLogin Fehler: Passwort falsch.");
                    let suffix = '/login?error=2';
                    if (redirect_uri) {
                        suffix += '&redirect_uri=' + encodeURIComponent(redirect_uri);
                    }
                    if (state) {
                        suffix += '&state=' + encodeURIComponent(state);
                    }
                    return res.redirect(suffix);
                }
            });
        });
    }
}