// noinspection JSCheckFunctionSignatures

import * as redis from "redis";
import argon2 from "argon2";

const rc = redis.createClient({
    socket: {
        host: process.env.REDIS_HOST,
        port: process.env.REDIS_PORT
    }
});

rc.on('error', err => {
    console.log('Redis Error: ' + err);
});

// noinspection GrazieInspection
function escape(text) {
    return text.replaceAll(':', '%58') // Ersetze alle : durch %58
}

export async function startDB() {
    return rc.connect()
}

export async function hash(password) {
    return await argon2.hash(password, { type: argon2.argon2id });
}

export async function verifyHash(password, storedHash) {
    try {
        return await argon2.verify(storedHash, password);
    } catch (err) {
        console.error('Error verifying hash:', err);
        return false;
    }
}

export function getUUIDByUsername(username) {
    return rc.hGet("guard:usernames", username);
}

export function checkPassword(uuid, password) {
    return rc.hGet("guard:user:" + escape(uuid), "password").then(value => {
        if (value !== undefined && value !== null) {
            return verifyHash(uuid + password, value);
        }
        return false
    })
}

export function getDisplayname(uuid) {
    return rc.hGet("guard:user:" + escape(uuid), "displayname")
}

export function setDisplayname(uuid, displayname) {
    return rc.hSet("guard:user:" + escape(uuid), "displayname", displayname)
}

export function setUsername(uuid, username) {
    return getUsername(uuid).then((oldUsername) => {
        return rc.hDel("guard:usernames", oldUsername).then(() => {
            return rc.hSet("guard:usernames", username, escape(uuid)).then(() => {
                return rc.hSet("guard:user:" + escape(uuid), "username", username)
            })
        })
    })
}

export async function setPassword(uuid, password) {
    const hashed = await hash(uuid + password);
    return rc.hSet("guard:user:" + escape(uuid), "password", hashed);
}

export async function storeUser(uuid, username, password, displayname) {
    const now = Date.now();
    const hashed = await hash(uuid + password);
    await rc.hSet("guard:user:" + escape(uuid), "password", hashed);
    await rc.hSet("guard:user:" + escape(uuid), "displayname", displayname);
    await rc.hSet("guard:user:" + escape(uuid), "username", username);
    await rc.hSet("guard:usernames", username, uuid);
    await rc.hSet("guard:user:" + escape(uuid), "creation", now);
    await rc.hSet("guard:user:" + escape(uuid), "lastLogin", now);
    return;
}

export function updateLastLogin(uuid) {
    return rc.hSet("guard:user:" + escape(uuid), "lastLogin", Date.now());
}


export function getUsername(uuid) {
    return rc.hGet("guard:user:" + escape(uuid), "username")
}

export function isUsernameAvailable(username) {
    return rc.hExists("guard:usernames", username)
}

export async function getAllUsers() {
    const usernames = await rc.hGetAll("guard:usernames");
    const uuids = Object.values(usernames);
    const users = [];
    for (const uuid of uuids) {
        const data = await rc.hGetAll("guard:user:" + escape(uuid));
        users.push({
            uuid,
            displayname: data.displayname,
            username: data.username,
            creation: data.creation ? new Date(Number(data.creation)).toLocaleString() : "",
            lastLogin: data.lastLogin ? new Date(Number(data.lastLogin)).toLocaleString() : ""
        });
    }
    return users;
}

// Passkey-Funktionen
export async function storePasskey(user,passkeyData) {
    const { id, publicKey, webAuthnUserID, counter, deviceType, backedUp, transports } = passkeyData;
    
    // Speichere den Passkey unter guard:passkey:{id}
    const passkeyKey = "guard:passkey:" + escape(id);
    
    await rc.hSet(passkeyKey, {
        "id": id,
        "publicKey": Buffer.from(publicKey).toString('base64'), // Uint8Array als Base64 String speichern
        "user": user,
        "webauthnUserID": webAuthnUserID,
        "counter": counter.toString(),
        "deviceType": deviceType,
        "backedUp": backedUp.toString(),
        "transports": transports ? transports.join(',') : '' // Array als CSV String
    });

    // Indexierung: Passkey ID zum Benutzer zuordnen
    await rc.hSet("guard:user:" + escape(user) + ":passkeys", id, "1");

    // Indexierung: webAuthnUserID für schnelle Suche
    await rc.hSet("guard:webauthn:userids", webAuthnUserID, user);
    
    return;
}

export async function getPasskey(id) {
    const data = await rc.hGetAll("guard:passkey:" + escape(id));
    
    if (!data || Object.keys(data).length === 0) {
        return null;
    }
    
    return {
        id: data.id,
        publicKey: new Uint8Array(Buffer.from(data.publicKey, 'base64')), // Base64 String zurück zu Uint8Array
        user: data.user,
        webauthnUserID: data.webauthnUserID,
        counter: parseInt(data.counter),
        deviceType: data.deviceType,
        backedUp: data.backedUp === 'true',
        transports: data.transports ? data.transports.split(',').filter(t => t.length > 0) : []
    };
}

export async function getUserPasskeys(uuid) {
    const passkeyIds = await rc.hKeys("guard:user:" + escape(uuid) + ":passkeys");
    console.log("Passkey IDs für Nutzer", uuid, passkeyIds);
    const passkeys = [];
    
    for (const id of passkeyIds) {
        const passkey = await getPasskey(id);
        console.log("Passkey für Nutzer", uuid, id, passkey);
        if (passkey) {
            passkeys.push(passkey);
        }
    }
    
    return passkeys;
}

export async function getUserByWebAuthnID(webauthnUserID) {
    return rc.hGet("guard:webauthn:userids", webauthnUserID);
}

export async function updatePasskeyCounter(id, newCounter) {
    return rc.hSet("guard:passkey:" + escape(id), "counter", newCounter.toString());
}

export async function deletePasskey(id) {
    const passkey = await getPasskey(id);
    if (!passkey) {
        return false;
    }
    
    // Entferne den Passkey vom Benutzer
    await rc.hDel("guard:user:" + escape(passkey.user) + ":passkeys", id);
    
    // Entferne den Passkey selbst
    await rc.del("guard:passkey:" + escape(id));
    
    return true;
}

export async function getPasskeysByWebAuthnUserID(webauthnUserID) {
    const uuid = await getUserByWebAuthnID(webauthnUserID);
    if (!uuid) {
        return [];
    }
    
    return getUserPasskeys(uuid);
}