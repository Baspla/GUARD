// noinspection SpellCheckingInspection

import {v4 as generateuuid} from "uuid";
import {
    checkPassword,
    getDisplayname, getUsername, getUUIDByToken, getUUIDByUsername,
    isUsernameAvailable,
    setDisplayname, setPassword, setUsername,
    storeToken,
    storeUser
} from "./db.js";
import {isDisplaynameValid, isPasswordValid, isUsernameValid} from "./validator.js";

export function login(req, res) {
    const {returnURL, error} = req.query;
    if (isLoggedIn(req)) {
        if (returnURL == null) { // Nutzer ist bereits eingeloggt ohne ServiceURL
            return res.redirect("/");
        } else { // Nutzer ist bereits eingeloggt mit ServiceURL
            let hostname
            try {
                const url = new URL(returnURL)
                hostname = url.hostname
            } catch (e) {
                let err = new Error("Die angegebene returnURL ist ungültig.")
                err.status = 400
                throw err
            }
            return getUsername(req.session.uuid).then(username => {
                return res.render('prompt', {
                    username: username,
                    returnURL: returnURL,
                    hostname: hostname,
                    error: error,
                    title: "Bestätigen"
                });
            })
        }
    } else {
        if (returnURL == null) { // Nutzer ist nicht eingeloggt ohne ServiceURL
            return res.render("login", {registerSuffix: "", error: error, title: "Anmelden"});
        } else { // Nutzer ist nicht eingeloggt mit ServiceURL
            let hostname
            try {
                const url = new URL(returnURL)
                hostname = url.hostname
            } catch (e) {
                let err = new Error("Die angegebene returnURL ist ungültig.")
                err.status = 400
                throw err
            }
            return res.render("login", {
                registerSuffix: "?returnURL=" + returnURL,
                error: error,
                hostname: hostname,
                title: "Anmelden"
            });
        }
    }

}

export function logout(req, res) {
    const {returnURL} = req.query;
    req.session.destroy();
    if (returnURL != null) {
        return res.redirect('/login?returnURL=' + returnURL);
    }
    res.render('logout', {title: "Abgemeldet"})
}


export function registerUser(req, res) {
    if (isLoggedIn(req)) {
        return res.redirect('/')
    }
    const {error} = req.query;
    return res.render("register", {error: error, title: "Registrieren"});
}

export function doRegisterUser(req, res, next) {
    const {username, password, passwordRepeat, displayname} = req.body;
    const {returnURL} = req.query;
    let suffix = "";
    if (returnURL != null) {
        suffix = "&returnURL=" + returnURL;
    }
    if (password !== passwordRepeat) {
        return res.redirect('/register?error=5' + suffix);
    }
    if (!isUsernameValid(username)) {
        return res.redirect('/register?error=7' + suffix);
    }
    if (!isPasswordValid(password)) {
        return res.redirect('/register?error=10' + suffix)
    }
    if (!isDisplaynameValid(displayname)) {
        return res.redirect('/register?error=4' + suffix)
    }
    isUsernameAvailable(username).then((exists) => {
        if (exists) {
            return res.redirect('/register?error=6' + suffix);
        } else {
            let uuid = generateuuid();
            storeUser(uuid, username, password, displayname).then(() => {
                console.log("Registered user: " + username + " with UUID: " + uuid + " and displayname: " + displayname);
                req.session.uuid = uuid;
                if (returnURL == null) {
                    return res.redirect('/login');
                } else {
                    return res.redirect('/login?returnURL=' + returnURL);
                }
            }).catch((err) => {
                next(err);
            });
        }
    }).catch((err) => {
        next(err);
    });
}

function registerTokenAndRedirect(req, res, returnURL) {
    let id = generateuuid();
    console.debug("Generated token: " + id + " for user: " + req.session.uuid + " and returnURL: " + returnURL);
    storeToken(req.session.uuid, id).then(() => {
        var url = new URL(returnURL);
        url.searchParams.append('GUARDTOKEN', id);
        res.redirect(url);
    })
}

export function sso(req, res) {
    const {GUARDTOKEN} = req.query;
    if (GUARDTOKEN == null) {
        return res.status(400).json({error: "GUARDTOKEN fehlt.", code: 400})
    }
    getUUIDByToken(GUARDTOKEN).then((uuid) => {
        if (uuid == null) {
            return res.status(400).json({error: "GUARDTOKEN ist ungültig.", code: 400})
        }
        getDisplayname(uuid).then((displayname) => {
            res.status(200).json({uuid: uuid, displayname: displayname})
        })
    })
}

function isLoggedIn(req) {
    return req.session.uuid != null;
}

export function dashboard(req, res) {
    const {returnURL, error} = req.query;
    if (!isLoggedIn(req)) {
        if (returnURL == null) {
            return res.redirect('/login');
        } else {
            return res.redirect('/login?returnURL=' + returnURL);
        }
    }
    let uname = getUsername(req.session.uuid)
    let dname = getDisplayname(req.session.uuid)
    Promise.all([uname, dname]).then((values) => {
        res.render('dashboard', {username: values[0], displayname: values[1], error: error, title: "Dashboard"});
    })
}

export function displaynamechange(req, res) {
    if (!isLoggedIn(req)) {
        return res.redirect('/');
    }
    let uname = getUsername(req.session.uuid)
    let dname = getDisplayname(req.session.uuid)
    Promise.all([uname, dname]).then((values) => {
        res.render('changeDisplay', {username: values[0], displayname: values[1],title: "Displayname ändern"});
    })
}

export function usernamechange(req, res) {
    if (!isLoggedIn(req)) {
        return res.redirect('/');
    }
    getUsername(req.session.uuid).then((username) => {
        res.render('changeUsername', {username: username,title: "Nutzername ändern"});
    })
}

export function passwordchange(req, res) {
    if (!isLoggedIn(req)) {
        return res.redirect('/');
    }
    getUsername(req.session.uuid).then((username) => {
        res.render('changePassword', {username: username,title: "Passwort ändern"});
    })
}



export function doDisplaynamechange(req, res) {
    if (!isLoggedIn(req)) {
        return res.redirect('/')
    }
    const {displayname} = req.body;
    if (displayname == null) {
        return res.redirect('/displaynamechange?error=3')
    }
    if (!isDisplaynameValid(displayname)) {
        return res.redirect('/displaynamechange?error=4')
    }
    setDisplayname(req.session.uuid, displayname).then(() => {
        res.redirect('/')
    })
}

export function doUsernamechange(req, res) {
    if (!isLoggedIn(req)) {
        return res.redirect('/')
    }
    const {username} = req.body;
    if (username == null) {
        return res.redirect('/usernamechange?error=8')
    }
    if (!isUsernameValid(username)) {
        return res.redirect('/usernamechange?error=7')
    }
    setUsername(req.session.uuid, username).then(() => {
        res.redirect('/')
    })
}

export function doPasswordchange(req, res) {
    if (!isLoggedIn(req)) {
        return res.redirect('/')
    }
    const {password, passwordRepeat, oldPassword} = req.body;
    if (password == null || passwordRepeat == null || oldPassword == null) {
        return res.redirect('/passwordchange?error=9')
    }
    if (!isPasswordValid(password)) {
        return res.redirect('/passwordchange?error=10')
    }
    if (password !== passwordRepeat) {
        return res.redirect('/?error=5')
    }
    if (!checkPassword(req.session.uuid, oldPassword)) {
        return res.redirect('/?error=11')
    }
    setPassword(req.session.uuid, password).then(() => {
        res.redirect('/')
    })
}


export function doLogin(req, res) {
    const {username, password, confirmed} = req.body;
    const {returnURL} = req.query;
    if ((username == null || password == null) && confirmed !== "true") {
        if (returnURL != null) {
            res.redirect('/login?error=1')
        } else {
            res.redirect('/login?error=1&returnURL=' + returnURL)
        }
    }
    if (confirmed === "true") {
        if (isLoggedIn(req)) {
            return registerTokenAndRedirect(req, res, returnURL)
        } else {
            return res.redirect('/login?error=1')
        }
    } else {
        getUUIDByUsername(username).then((uuid) => {
            if (uuid == null) {
                if (returnURL == null) {
                    return res.redirect('/login?error=2')
                } else {
                    return res.redirect('/login?error=2&returnURL=' + returnURL)
                }
            }
            checkPassword(uuid, password).then((result) => {
                if (result) {
                    req.session.uuid = uuid;
                    if (returnURL != null) {
                        return registerTokenAndRedirect(req, res, returnURL)
                    } else {
                        return res.redirect("/");
                    }
                } else {
                    if (returnURL == null) {
                        return res.redirect('/login?error=2')
                    } else {
                        return res.redirect('/login?error=2&returnURL=' + returnURL)
                    }
                }
            })
        })
    }
}