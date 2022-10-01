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

export function checkUser(username,password) {
    return rc.hGet("guard:user:" + escape(username), "password").then(value => {
        if (value !== undefined && value !== null) {
            return value === hash(username+password)
        }
        return false
    })
}
export function storeToken(username,token){
    return rc.set("guard:token:" + escape(token), username).then(() => {
        return rc.expire("guard:token:" + escape(token), 60*60) //Token verfällt nach einer Stunde
    })
}

export function getUsernameByToken(token){
    return rc.get("guard:token:" + escape(token))
}
export function getDisplayname(username){
    return rc.hGet("guard:user:" + escape(username), "displayname")
}
export function setDisplayname(username,displayname){
    return rc.hSet("guard:user:" + escape(username), "displayname", displayname)
}
export function setPassword(username,password){
    return rc.hSet("guard:user:" + escape(username), "password", hash(username+password))
}

export function storeUser(username,password,displayname){
    return rc.hSet("guard:user:" + escape(username), "password", hash(username+password)).then(() => {
        return rc.hSet("guard:user:" + escape(username), "displayname", displayname)
    })
}
export function isUsernameAvailable(username){
    return rc.exists("guard:user:" + escape(username))
}