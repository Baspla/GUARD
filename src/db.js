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
    return crypto.createHash('sha256').update(password).digest('base64');
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
            return value === hash(uuid + password)
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
            return rc.hSet("guard:usernames", "username", username).then(() => {
                return rc.hSet("guard:user:" + escape(uuid), "username", username)
            })
        })
    })
}

export function setPassword(uuid, password) {
    return rc.hSet("guard:user:" + escape(uuid), "password", hash(uuid + password))
}

export function storeUser(uuid, username, password, displayname) {
    return rc.hSet("guard:user:" + escape(uuid), "password", hash(uuid + password)).then(() => {
        return rc.hSet("guard:user:" + escape(uuid), "displayname", displayname).then(() => {
            return rc.hSet("guard:user:" + escape(uuid), "username", username).then(
                () => {
                    return rc.hSet("guard:usernames", username, uuid)
                }
            )
        })
    })
}

export function getUsername(uuid) {
    return rc.hGet("guard:user:" + escape(uuid), "username")
}

export function isUsernameAvailable(username) {
    return rc.hExists("guard:usernames", username)
}