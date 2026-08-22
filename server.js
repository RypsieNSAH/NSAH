const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const Database = require("better-sqlite3");

const app = express();

const PORT = 3000;


/* =====================================================
   FESTER PFAD ZUR DATENBANK
===================================================== */

const datenbankPfad =
    path.join(__dirname, "nsah.db");

const db =
    new Database(datenbankPfad);


/* =====================================================
   DATENBANK INITIALISIEREN
===================================================== */

db.pragma("journal_mode = WAL");

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
`);


/* =====================================================
   EXPRESS
===================================================== */

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
);


/* =====================================================
   SESSION
===================================================== */

app.use(
    session({
        secret: "NSAH-Geheimer-Schluessel-2026",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                30
        }
    })
);


/* =====================================================
   WEBSITE
===================================================== */

app.use(
    express.static(__dirname)
);


app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "index.html"
        )
    );

});


/* =====================================================
   REGISTRIEREN
===================================================== */

app.post(
    "/api/register",
    async (req, res) => {

        try {

            let {
                username,
                email,
                password
            } = req.body;


            username =
                String(username || "")
                    .trim();

            email =
                String(email || "")
                    .trim()
                    .toLowerCase();

            password =
                String(password || "");


            if (
                !username ||
                !email ||
                !password
            ) {

                return res.json({

                    success: false,

                    message:
                        "Bitte alle Felder ausfüllen."

                });

            }


            if (
                password.length < 6
            ) {

                return res.json({

                    success: false,

                    message:
                        "Das Passwort muss mindestens 6 Zeichen haben."

                });

            }


            /* Prüfen, ob E-Mail existiert */

            const vorhandenerBenutzer =
                db.prepare(
                    `
                    SELECT id
                    FROM users
                    WHERE email = ?
                    `
                ).get(email);


            if (vorhandenerBenutzer) {

                return res.json({

                    success: false,

                    message:
                        "Diese E-Mail-Adresse ist bereits registriert. Bitte melde dich an."

                });

            }


            /* Passwort hashen */

            const passwortHash =
                await bcrypt.hash(
                    password,
                    12
                );


            /* Benutzer dauerhaft speichern */

            const ergebnis =
                db.prepare(
                    `
                    INSERT INTO users
                    (
                        username,
                        email,
                        password
                    )
                    VALUES (?, ?, ?)
                    `
                ).run(
                    username,
                    email,
                    passwortHash
                );


            /* Session erstellen */

            req.session.userId =
                Number(
                    ergebnis.lastInsertRowid
                );


            req.session.save(
                (sessionError) => {

                    if (sessionError) {

                        console.error(
                            "Session-Fehler:",
                            sessionError
                        );

                        return res.status(500).json({

                            success: false,

                            message:
                                "Konto wurde gespeichert, aber die Anmeldung konnte nicht gespeichert werden."

                        });

                    }


                    console.log(
                        "Neuer Benutzer gespeichert:",
                        username,
                        email
                    );


                    res.json({

                        success: true,

                        username:
                            username,

                        email:
                            email

                    });

                }
            );

        } catch (error) {

            console.error(
                "Registrierungsfehler:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Bei der Registrierung ist ein Fehler aufgetreten."

            });

        }

    }
);


/* =====================================================
   ANMELDEN
===================================================== */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            let {
                email,
                password
            } = req.body;


            email =
                String(email || "")
                    .trim()
                    .toLowerCase();

            password =
                String(password || "");


            if (
                !email ||
                !password
            ) {

                return res.json({

                    success: false,

                    message:
                        "Bitte E-Mail und Passwort eingeben."

                });

            }


            /* Benutzer aus SQLite laden */

            const user =
                db.prepare(
                    `
                    SELECT *
                    FROM users
                    WHERE email = ?
                    `
                ).get(email);


            if (!user) {

                return res.json({

                    success: false,

                    message:
                        "Dieses Konto existiert nicht."

                });

            }


            /* Passwort prüfen */

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


            /* Session setzen */

            req.session.userId =
                user.id;


            req.session.save(
                (sessionError) => {

                    if (sessionError) {

                        console.error(
                            "Session-Fehler:",
                            sessionError
                        );

                        return res.status(500).json({

                            success: false,

                            message:
                                "Die Anmeldung konnte nicht gespeichert werden."

                        });

                    }


                    console.log(
                        "Benutzer angemeldet:",
                        user.username
                    );


                    res.json({

                        success: true,

                        username:
                            user.username,

                        email:
                            user.email

                    });

                }
            );

        } catch (error) {

            console.error(
                "Anmeldefehler:",
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Bei der Anmeldung ist ein Fehler aufgetreten."

            });

        }

    }
);


/* =====================================================
   AKTUELLER BENUTZER
===================================================== */

app.get(
    "/api/me",
    (req, res) => {

        if (!req.session.userId) {

            return res.json({

                loggedIn: false

            });

        }


        const user =
            db.prepare(
                `
                SELECT
                    id,
                    username,
                    email
                FROM users
                WHERE id = ?
                `
            ).get(
                req.session.userId
            );


        if (!user) {

            req.session.destroy(
                () => {}
            );


            return res.json({

                loggedIn: false

            });

        }


        res.json({

            loggedIn: true,

            username:
                user.username,

            email:
                user.email

        });

    }
);


/* =====================================================
   ABMELDEN
===================================================== */

app.post(
    "/api/logout",
    (req, res) => {

        req.session.destroy(
            (error) => {

                if (error) {

                    console.error(
                        "Logout-Fehler:",
                        error
                    );


                    return res.status(500).json({

                        success: false,

                        message:
                            "Abmelden fehlgeschlagen."

                    });

                }


                res.clearCookie(
                    "connect.sid"
                );


                res.json({

                    success: true

                });

            }
        );

    }
);


/* =====================================================
   SERVER START
===================================================== */

app.listen(
    PORT,
    () => {

        console.log("");
        console.log(
            "=============================="
        );
        console.log(
            "          NSAH SERVER"
        );
        console.log(
            "=============================="
        );
        console.log("");

        console.log(
            "NSAH läuft auf:"
        );

        console.log(
            "http://localhost:" +
            PORT
        );

        console.log("");

        console.log(
            "Datenbank:"
        );

        console.log(
            datenbankPfad
        );

        console.log("");

    }
);
