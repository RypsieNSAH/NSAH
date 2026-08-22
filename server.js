const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const Database = require("better-sqlite3");

const app = express();

const PORT = 3000;


/* =========================
   DATENBANK
   ========================= */

const db = new Database("nsah.db");


db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
`);


/* =========================
   EXPRESS
   ========================= */

app.use(express.json());

app.use(express.urlencoded({
    extended: true
}));


/* =========================
   SITZUNG / LOGIN
   ========================= */

app.use(
    session({
        secret: "NSAH-Geheimer-Schluessel-2026",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            maxAge: 1000 * 60 * 60 * 24 * 7
        }
    })
);


/* =========================
   INDEX.HTML AUSLIEFERN
   ========================= */

app.use(express.static(__dirname));


app.get("/", (req, res) => {

    res.sendFile(
        path.join(__dirname, "index.html")
    );

});


/* =========================
   REGISTRIEREN
   ========================= */

app.post("/api/register", async (req, res) => {

    try {

        const {
            username,
            email,
            password
        } = req.body;


        /* Felder überprüfen */

        if (
            !username ||
            !email ||
            !password
        ) {

            return res.json({
                success: false,
                message: "Bitte alle Felder ausfüllen."
            });

        }


        /* Passwortlänge */

        if (password.length < 6) {

            return res.json({
                success: false,
                message:
                    "Das Passwort muss mindestens 6 Zeichen haben."
            });

        }


        /* Prüfen, ob E-Mail bereits existiert */

        const vorhandenerBenutzer =
            db.prepare(
                "SELECT id FROM users WHERE email = ?"
            ).get(email);


        if (vorhandenerBenutzer) {

            return res.json({
                success: false,
                message:
                    "Diese E-Mail-Adresse ist bereits registriert."
            });

        }


        /* Passwort sicher hashen */

        const passwortHash =
            await bcrypt.hash(
                password,
                12
            );


        /* Benutzer speichern */

        const ergebnis =
            db.prepare(`
                INSERT INTO users
                (
                    username,
                    email,
                    password
                )
                VALUES (?, ?, ?)
            `).run(
                username,
                email,
                passwortHash
            );


        /* Benutzer direkt einloggen */

        req.session.userId =
            ergebnis.lastInsertRowid;


        res.json({
            success: true,
            username: username,
            email: email
        });


    } catch (error) {

        console.error(
            "Registrierungsfehler:",
            error
        );


        res.json({
            success: false,
            message:
                "Bei der Registrierung ist ein Fehler aufgetreten."
        });

    }

});


/* =========================
   ANMELDEN
   ========================= */

app.post("/api/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;


        /* Benutzer suchen */

        const user =
            db.prepare(
                "SELECT * FROM users WHERE email = ?"
            ).get(email);


        if (!user) {

            return res.json({
                success: false,
                message:
                    "E-Mail oder Passwort ist falsch."
            });

        }


        /* Passwort überprüfen */

        const passwortRichtig =
            await bcrypt.compare(
                password,
                user.password
            );


        if (!passwortRichtig) {

            return res.json({
                success: false,
                message:
                    "E-Mail oder Passwort ist falsch."
            });

        }


        /* Login speichern */

        req.session.userId =
            user.id;


        res.json({
            success: true,
            username: user.username,
            email: user.email
        });


    } catch (error) {

        console.error(
            "Anmeldefehler:",
            error
        );


        res.json({
            success: false,
            message:
                "Bei der Anmeldung ist ein Fehler aufgetreten."
        });

    }

});


/* =========================
   AKTUELL ANGEMELDETEN
   BENUTZER ABFRAGEN
   ========================= */

app.get("/api/me", (req, res) => {

    if (!req.session.userId) {

        return res.json({
            loggedIn: false
        });

    }


    const user =
        db.prepare(`
            SELECT
                id,
                username,
                email
            FROM users
            WHERE id = ?
        `).get(
            req.session.userId
        );


    if (!user) {

        return res.json({
            loggedIn: false
        });

    }


    res.json({
        loggedIn: true,
        username: user.username,
        email: user.email
    });

});


/* =========================
   ABMELDEN
   ========================= */

app.post("/api/logout", (req, res) => {

    req.session.destroy((error) => {

        if (error) {

            return res.json({
                success: false,
                message:
                    "Abmelden fehlgeschlagen."
            });

        }


        res.json({
            success: true
        });

    });

});


/* =========================
   SERVER STARTEN
   ========================= */

app.listen(PORT, () => {

    console.log("");
    console.log("==============================");
    console.log("       NSAH SERVER");
    console.log("==============================");
    console.log("");
    console.log(
        "NSAH läuft auf http://localhost:" + PORT
    );
    console.log("");

});