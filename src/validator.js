export function isDisplaynameValid(displayname) {
    return displayname.length <= 32 && displayname.length >= 3;
}