import {v4 as uuid} from "uuid";
import {
    checkUser,
    getDisplayname,
    getUsernameByToken,
    isUsernameAvailable,
    setDisplayname,
    storeToken,
    storeUser
} from "./db.js";
import {isDisplaynameValid} from "./validator.js";

export function logout(req, res) {
    const {returnURL} = req.query;
    req.session.destroy();
    if (returnURL != null) {
        return res.redirect('/login?returnURL=' + returnURL);
    }
    res.render('logout',{title:"Abgemeldet"})
}

export function login(req, res, next) {
    const {returnURL, error} = req.query;
    if (req.session.username != null) {
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
            return res.render('prompt', {username: req.session.username, returnURL: returnURL, hostname: hostname,error:error,title:"Bestätigen"});
        }
    } else {
        if (returnURL == null) { // Nutzer ist nicht eingeloggt ohne ServiceURL
            return res.render("login", {registerSuffix: "", error: error,title:"Anmelden"});
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
            return res.render("login", {registerSuffix: "?returnURL=" + returnURL, error: error,hostname:hostname,title:"Anmelden"});
        }
    }

}

export function registerUser(req, res, next) {
    if(req.session.username != null){
        return res.redirect('/')
    }
    const {error} = req.query;
    return res.render("register", {error:error,title:"Registrieren"});
}

export function doRegisterUser(req,res,next){
    const {username, password, passwordRepeat,displayname} = req.body;
    const {returnURL} = req.query;
    if (password !== passwordRepeat) {
        if(returnURL == null){
            return res.redirect('/register?error=5');
        }else{
            return res.redirect('/register?error=5&returnURL='+returnURL);
        }
    }
    if(!isUsernameValid(username)){
        if(returnURL == null){
            return res.redirect('/register?error=7');
        }else{
            return res.redirect('/register?error=7&returnURL='+returnURL);
        }
    }
    isUsernameAvailable(username).then((exists) => {
        if (exists) {
            if(returnURL == null){
                return res.redirect('/register?error=6');
            }else{
                return res.redirect('/register?error=6&returnURL='+returnURL);
            }
        } else {
            if(isDisplaynameValid(displayname)){
                storeUser(username, password,displayname).then(() => {
                    req.session.username = username;
                    if(returnURL == null){
                        return res.redirect('/login');
                    }else{
                        return res.redirect('/login?returnURL='+returnURL);
                    }
                }).catch((err) => {
                    next(err);
                });
            }else{
                if(returnURL == null){
                    return res.redirect('/register?error=4');
                }else{
                    return res.redirect('/register?error=4&returnURL='+returnURL);
                }
            }
        }
    }).catch((err) => {
        next(err);
    });
}

function registerTokenAndRedirect(req, res, returnURL) {
    let id = uuid();
    console.debug("Generated token: " + id+ " for user: " + req.session.username + " and returnURL: " + returnURL);
    storeToken(req.session.username,id).then(() => {
        res.redirect(`${returnURL}?GUARDTOKEN=${id}`);
    })
}

export function sso(req, res, next) {
    const {GUARDTOKEN} = req.query;
    if (GUARDTOKEN == null) {
        return res.status(400).json({error: "GUARDTOKEN fehlt.", code: 400})
    }
    getUsernameByToken(GUARDTOKEN).then((username) => {
        if (username == null) {
            return res.status(400).json({error: "GUARDTOKEN ist ungültig.", code: 400})
        }
        getDisplayname(username).then((displayname) => {
            res.status(200).json({username: username,displayname: displayname})
        })
    })
}

export function dashboard(req, res, next) {
    const {returnURL, error} = req.query;
    if (req.session.username == null) {
        if(returnURL == null){
            return res.redirect('/login');
        }else {
            return res.redirect('/login?returnURL=' + returnURL);
        }
    }
    getDisplayname(req.session.username).then((displayname) => {
        res.render('dashboard', {username: req.session.username, displayname: displayname,error: error,title:"Dashboard"});
    })
}

export function namechange(req, res, next) {
    if(req.session.username == null){
        return res.redirect('/')
    }
    const {displayname} = req.body;
    if (displayname == null) {
        return res.redirect('/?error=3')
    }
    if(!isDisplaynameValid(displayname)){
        return res.redirect('/?error=4')
    }
    setDisplayname(req.session.username, displayname).then(() => {
        res.redirect('/')
    })
}

export function doLogin(req, res, next) {
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
        if(req.session.username) {
            return registerTokenAndRedirect(req, res, returnURL)
        } else {
            return res.redirect('/login?error=1')
        }
    } else {
        checkUser(username, password).then((result) => {
            if (result) {
                req.session.username = username;
                if (returnURL != null) {
                    return registerTokenAndRedirect(req, res, returnURL)
                } else {
                    return res.redirect("/");
                }
            } else {
                if (returnURL == null) {
                    res.redirect('/login?error=2')
                } else {
                    res.redirect('/login?error=2&returnURL=' + returnURL)
                }
            }
        })
    }
}