// Minimal helper for WebAuthn interactions used by the server views
// Provides performCreate and performGet which wrap navigator.credentials
function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let str = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        str += String.fromCharCode(bytes[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBuffer(base64url) {
    const b64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
    const bin = atob(b64 + pad);
    const buffer = new ArrayBuffer(bin.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return buffer;
}

async function transformCreateOptions(opts) {
    const publicKey = Object.assign({}, opts);
    publicKey.challenge = base64urlToBuffer(opts.challenge);
    publicKey.user.id = base64urlToBuffer(opts.user.id);
    if (publicKey.excludeCredentials) {
        publicKey.excludeCredentials = publicKey.excludeCredentials.map(c => Object.assign({}, c, { id: base64urlToBuffer(c.id) }));
    }
    return publicKey;
}

async function transformGetOptions(opts) {
    const publicKey = Object.assign({}, opts);
    publicKey.challenge = base64urlToBuffer(opts.challenge);
    if (publicKey.allowCredentials) {
        publicKey.allowCredentials = publicKey.allowCredentials.map(c => Object.assign({}, c, { id: base64urlToBuffer(c.id) }));
    }
    return publicKey;
}

export async function performCreate(opts) {
    const publicKey = await transformCreateOptions(opts);
    const cred = await navigator.credentials.create({ publicKey });
    const attestation = cred.response;
    return {
        id: cred.id,
        rawId: bufferToBase64url(cred.rawId),
        type: cred.type,
        response: {
            attestationObject: bufferToBase64url(attestation.attestationObject),
            clientDataJSON: bufferToBase64url(attestation.clientDataJSON)
        }
    };
}

export async function performGet(opts) {
    const publicKey = await transformGetOptions(opts);
    const assertion = await navigator.credentials.get({ publicKey });
    const auth = assertion.response;
    return {
        id: assertion.id,
        rawId: bufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
            authenticatorData: bufferToBase64url(auth.authenticatorData),
            clientDataJSON: bufferToBase64url(auth.clientDataJSON),
            signature: bufferToBase64url(auth.signature),
            userHandle: auth.userHandle ? bufferToBase64url(auth.userHandle) : null
        }
    };
}

// expose helpers to window for inline usage in pug
window.performCreate = performCreate;
window.performGet = performGet;
