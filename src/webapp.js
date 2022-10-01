import express from "express";
import session from 'express-session'
import cookieParser from 'cookie-parser';
import { startDB} from "./db.js";
import {fileURLToPath} from 'url';
import {dirname} from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const webapp = express()

webapp.use(cookieParser());
webapp.use(session({
    secret: process.env.SECRET,
    resave: true,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 24
    }
}))

webapp.set('view engine', 'pug')
webapp.set('views', __dirname+ '/../views')
webapp.use('/css', express.static(__dirname + '/../node_modules/bootstrap/dist/css'))
webapp.use('/js', express.static(__dirname + '/../node_modules/bootstrap/dist/js'))
webapp.use('/favicon.ico', express.static(__dirname + '/../public/images/favicon.ico'))
webapp.use('/scripts', express.static(__dirname + '/../public/javascript'))
webapp.use('/sheets', express.static(__dirname + '/../public/css'))
webapp.use(express.json());

//
// WEP PAGES
//

webapp.get('/', (req, res) => {
    res.redirect("/login")
})

webapp.get('/register', (req, res) => {
        res.render('register')
})

webapp.get('/prompt', (req, res) => {
    res.render('prompt', {user: "Test User"})
})

webapp.get('/logout', (req, res) => {
    req.session.destroy();
    res.render('logout')
})

webapp.get('/login', (req, res) => {
    if (req.session.username) {
        res.render('prompt')
    }else {
        res.render('login')
    }
})

async function start() {
    await startDB().then(() => {
        console.log(`Verbindung zu Redis auf ${process.env.REDIS_HOST}:${process.env.REDIS_PORT} hergestellt.`)
        webapp.listen(80, () =>
            console.log(`Express wurde gestartet.`)
        );
    })
}

start().then(() => {
});
