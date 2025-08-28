// noinspection JSCheckFunctionSignatures

import * as redis from "redis";
import * as crypto from "crypto";

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

export function hash(password) {
    const salt = crypto.randomBytes(16).toString('base64');
    const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('base64');
    return `${salt}:${hash}`;
}

export function verifyHash(password, storedHash) {
    const [salt, hash] = storedHash.split(':');
    const hashedInput = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('base64');
    return hash === hashedInput;
}

export function getUUIDByToken(token) {
    return rc.get("guard:token:" + escape(token));
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

export function storeToken(uuid, token) {
    return rc.set("guard:token:" + escape(token), uuid).then(() => {
        return rc.expire("guard:token:" + escape(token), 60 * 60) //Token verfällt nach einer Stunde
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

export function setPassword(uuid, password) {
    return rc.hSet("guard:user:" + escape(uuid), "password", hash(uuid + password))
}

export function storeUser(uuid, username, password, displayname) {
    const now = Date.now();
    return rc.hSet("guard:user:" + escape(uuid), "password", hash(uuid + password))
        .then(() => rc.hSet("guard:user:" + escape(uuid), "displayname", displayname))
        .then(() => rc.hSet("guard:user:" + escape(uuid), "username", username))
        .then(() => rc.hSet("guard:usernames", username, uuid))
        .then(() => rc.hSet("guard:user:" + escape(uuid), "creation", now))
        .then(() => rc.hSet("guard:user:" + escape(uuid), "lastLogin", now));

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