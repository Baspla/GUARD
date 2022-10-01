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

function escape(text) {
    return text.replaceAll(':', '%58')
}

export async function startDB() {
    return rc.connect()
}

export function hash(password) {
    return crypto.createHash('sha256').update(password).digest('base64');
}
