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
    const {redirect_uri, error, state} = req.query;
    if (isLoggedIn(req)) {
        if (redirect_uri == null) { // Nutzer ist bereits eingeloggt ohne ServiceURL
            return res.redirect("/");
        } else { // Nutzer ist bereits eingeloggt mit ServiceURL
            let hostname
            try {
                const url = new URL(redirect_uri)
                hostname = url.hostname
            } catch (e) {
                let err = new Error("Die angegebene redirect_uri ist ungültig.")
                err.status = 400
                throw err
            }
            return getUsername(req.session.uuid).then(username => {
                return res.render('prompt', {
                    username: username,
                    redirect_uri: redirect_uri,
                    hostname: hostname,
                    error: error,
                    state: state,
                    title: "Bestätigen"
                });
            })
        }
    } else {
        if (redirect_uri == null) { // Nutzer ist nicht eingeloggt ohne ServiceURL
            return res.render("login", {registerSuffix: "", error: error, title: "Anmelden", state: state});
        } else { // Nutzer ist nicht eingeloggt mit ServiceURL
            let hostname
            try {
                const url = new URL(redirect_uri)
                hostname = url.hostname
            } catch (e) {
                let err = new Error("Die angegebene redirect_uri ist ungültig.")
                err.status = 400
                throw err
            }
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
    req.session.destroy();
    if (redirect_uri != null) {
        let suffix = '/login?redirect_uri=' + encodeURIComponent(redirect_uri);
        if (state) suffix += '&state=' + encodeURIComponent(state);
        return res.redirect(suffix);
    }
    res.render('logout', {title: "Abgemeldet"})
}


export function registerUser(req, res) {
    if (isLoggedIn(req)) {
        return res.redirect('/')
    }
    const {error, state, redirect_uri} = req.query;
    return res.render("register", {error: error, title: "Registrieren", state: state, redirect_uri: redirect_uri});
}

export function doRegisterUser(req, res, next) {
    const {username, password, passwordRepeat, displayname,secret} = req.body;
    const {redirect_uri, state} = req.query;
    let suffix = "";
    if (redirect_uri != null) {
        suffix = "&redirect_uri=" + encodeURIComponent(redirect_uri);
    }
    if (state) {
        suffix += "&state=" + encodeURIComponent(state);
    }
    if (secret !== process.env.REGISTER_SECRET) {
        return res.redirect('/register?error=12' + suffix);
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
        console.debug("Generated token: " + id + " for user: " + req.session.uuid + " and redirect_uri: " + returnURL);
        storeToken(req.session.uuid, id).then(() => {
            var url = new URL(returnURL);
            url.searchParams.append('code', id);
            if (state) url.searchParams.append('state', state);
            res.redirect(url);
        })
}

export function token(req, res) {
    const {code} = req.query;
    if (code == null) {
        return res.status(400).json({error: "code fehlt.", code: 400})
    }
    getUUIDByToken(code).then((uuid) => {
        if (uuid == null) {
            return res.status(400).json({error: "code ist ungültig.", code: 400})
        }
        getDisplayname(uuid).then((displayname) => {
            if (displayname == null) {
                return res.status(400).json({error: "UUID ist ungültig.", code: 400})
            }
            res.status(200).json({uuid: uuid, displayname: displayname})
        })
    })
}

export function getInformation(req, res) {
    const {uuid} = req.query;
    if (uuid == null) {
        return res.status(400).json({error: "UUID fehlt.", code: 400})
    }
    getDisplayname(uuid).then((displayname) => {
        if (displayname == null) {
            return res.status(400).json({error: "UUID ist ungültig.", code: 400})
        }
        res.status(200).json({uuid: uuid, displayname: displayname})
    })
}

function isLoggedIn(req) {
    return req.session.uuid != null;
}

export function dashboard(req, res) {
    const {redirect_uri, error, state} = req.query;
    if (!isLoggedIn(req)) {
        let suffix = '/login';
        if (redirect_uri) {
            suffix += '?redirect_uri=' + encodeURIComponent(redirect_uri);
            if (state) suffix += '&state=' + encodeURIComponent(state);
        }
        return res.redirect(suffix);
    }
    let uname = getUsername(req.session.uuid)
    let dname = getDisplayname(req.session.uuid)
    Promise.all([uname, dname]).then((values) => {
        res.render('dashboard', {username: values[0], displayname: values[1], error: error, title: "Dashboard", state: state, redirect_uri: redirect_uri});
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
    const {redirect_uri, state} = req.query;
    if ((username == null || password == null) && confirmed !== "true") {
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
            return registerTokenAndRedirect(req, res, redirect_uri, state)
        } else {
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
                    req.session.uuid = uuid;
                    if (redirect_uri != null) {
                        return registerTokenAndRedirect(req, res, redirect_uri, state)
                    } else {
                        return res.redirect("/");
                    }
                } else {
                    let suffix = '/login?error=2';
                    if (redirect_uri) {
                        suffix += '&redirect_uri=' + encodeURIComponent(redirect_uri);
                    }
                    if (state) {
                        suffix += '&state=' + encodeURIComponent(state);
                    }
                    return res.redirect(suffix);
                }
            })
        })
    }
}