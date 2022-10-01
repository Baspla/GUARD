export function isDisplaynameValid(displayname) {
    return displayname.length <= 32 && displayname.length >= 3;
}

export function isUsernameValid(username) {
    return username.length <= 32 && username.length >= 3 && username.match(/^[A-Za-z-_.\d]+$/) != null;
}

export function isPasswordValid(password) {
    return password.length >= 8;
}