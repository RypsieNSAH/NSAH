const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const Database = require("better-sqlite3");

const app = express();

const PORT = 3000;


/* =====================================================
   DATENBANK
===================================================== */

const db = new Database(
    path.join(__dirname, "nsah.db")
);


/*
   WAL-Modus macht SQLite stabiler,
   besonders wenn gleichzeitig gelesen
   und geschrieben wird.
*/

db.pragma("journal_mode = WAL");


/*
   Benutzer-Tabelle erstellen,
   falls sie noch nicht existiert.
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS users (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        username TEXT NOT NULL,

        email TEXT NOT NULL UNIQUE,

        password TEXT NOT NULL,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )
`);


/* =====================================================
   EXPRESS
===================================================== */

app.use(
    express.json()
);


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

        secret:
            process.env.SESSION_SECRET ||
            "NSAH-Geheimer-Schluessel-2026",

        resave: false,

        saveUninitialized: false,

        cookie: {

            httpOnly: true,

            /*
               7 Tage eingeloggt bleiben
            */

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                7,

            /*
               Lokal funktioniert "lax"
               zuverlässig.
            */

            sameSite: "lax",

            secure: false
        }

    })
);


/* =====================================================
   WEBSITE AUSLIEFERN
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


            /* =============================
               EINGABEN BEREINIGEN
            ============================= */

            username =
                String(
                    username || ""
                ).trim();


            email =
                String(
                    email || ""
                )
                .trim()
                .toLowerCase();


            password =
                String(
                    password || ""
                );


            /* =============================
               FELDER PRÜFEN
            ============================= */

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


            /* =============================
               BENUTZERNAME PRÜFEN
            ============================= */

            if (
                username.length < 3
            ) {

                return res.json({

                    success: false,

                    message:
                        "Der Benutzername muss mindestens 3 Zeichen haben."

                });

            }


            /* =============================
               PASSWORT PRÜFEN
            ============================= */

            if (
                password.length < 6
            ) {

                return res.json({

                    success: false,

                    message:
                        "Das Passwort muss mindestens 6 Zeichen haben."

                });

            }


            /* =============================
               E-MAIL PRÜFEN
            ============================= */

            if (
                !email.includes("@") ||
                !email.includes(".")
            ) {

                return res.json({

                    success: false,

                    message:
                        "Bitte gib eine gültige E-Mail-Adresse ein."

                });

            }


            /* =============================
               EXISTIERENDEN BENUTZER SUCHEN
            ============================= */

            const vorhandenerBenutzer =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email
                    FROM users
                    WHERE email = ?
                `).get(
                    email
                );


            if (
                vorhandenerBenutzer
            ) {

                return res.json({

                    success: false,

                    message:
                        "Diese E-Mail-Adresse ist bereits registriert. Bitte melde dich an."

                });

            }


            /* =============================
               PASSWORT HASHEN
            ============================= */

            const passwortHash =
                await bcrypt.hash(
                    password,
                    12
                );


            /* =============================
               BENUTZER SPEICHERN
            ============================= */

            const ergebnis =
                db.prepare(`
                    INSERT INTO users
                    (
                        username,
                        email,
                        password
                    )
                    VALUES
                    (
                        ?,
                        ?,
                        ?
                    )
                `).run(
                    username,
                    email,
                    passwortHash
                );


            /*
               WICHTIG:
               Die ID wird dauerhaft in SQLite gespeichert.
            */

            const userId =
                Number(
                    ergebnis.lastInsertRowid
                );


            /* =============================
               SESSION ERSTELLEN
            ============================= */

            req.session.userId =
                userId;


            /*
               Session explizit speichern.
               Dadurch wird verhindert,
               dass der Login-Zustand verloren geht.
            */

            req.session.save(
                (sessionError) => {

                    if (
                        sessionError
                    ) {

                        console.error(
                            "Session-Speicherfehler:",
                            sessionError
                        );

                        return res.status(500).json({

                            success: false,

                            message:
                                "Konto wurde gespeichert, aber der Login konnte nicht erstellt werden."

                        });

                    }


                    return res.json({

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


            /*
               Falls SQLite wegen
               UNIQUE einen Fehler meldet.
            */

            if (
                error.code ===
                "SQLITE_CONSTRAINT_UNIQUE"
            ) {

                return res.json({

                    success: false,

                    message:
                        "Diese E-Mail-Adresse ist bereits registriert."

                });

            }


            return res.status(500).json({

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
                String(
                    email || ""
                )
                .trim()
                .toLowerCase();


            password =
                String(
                    password || ""
                );


            /* =============================
               EINGABEN PRÜFEN
            ============================= */

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


            /* =============================
               BENUTZER SUCHEN
            ============================= */

            const user =
                db.prepare(`
                    SELECT
                        id,
                        username,
                        email,
                        password
                    FROM users
                    WHERE email = ?
                `).get(
                    email
                );


            if (!user) {

                return res.json({

                    success: false,

                    message:
                        "E-Mail oder Passwort ist falsch."

                });

            }


            /* =============================
               PASSWORT PRÜFEN
            ============================= */

            const passwortRichtig =
                await bcrypt.compare(
                    password,
                    user.password
                );


            if (
                !passwortRichtig
            ) {

                return res.json({

                    success: false,

                    message:
                        "E-Mail oder Passwort ist falsch."

                });

            }


            /* =============================
               SESSION SETZEN
            ============================= */

            req.session.userId =
                user.id;


            /*
               Session ausdrücklich speichern.
            */

            req.session.save(
                (sessionError) => {

                    if (
                        sessionError
                    ) {

                        console.error(
                            "Session-Speicherfehler:",
                            sessionError
                        );

                        return res.status(500).json({

                            success: false,

                            message:
                                "Login konnte nicht gespeichert werden."

                        });

                    }


                    return res.json({

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


            return res.status(500).json({

                success: false,

                message:
                    "Bei der Anmeldung ist ein Fehler aufgetreten."

            });

        }

    }
);


/* =====================================================
   AKTUELL ANGEMELDETEN BENUTZER ABFRAGEN
===================================================== */

app.get(
    "/api/me",
    (req, res) => {

        try {

            /*
               Keine Session vorhanden.
            */

            if (
                !req.session ||
                !req.session.userId
            ) {

                return res.json({

                    loggedIn: false

                });

            }


            /* =============================
               BENUTZER AUS DATENBANK LADEN
            ============================= */

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


            /*
               Benutzer existiert nicht mehr.
            */

            if (!user) {

                req.session.destroy(
                    () => {}
                );


                return res.json({

                    loggedIn: false

                });

            }


            /* =============================
               BENUTZER ZURÜCKGEBEN
            ============================= */

            return res.json({

                loggedIn: true,

                username:
                    user.username,

                email:
                    user.email

            });

        } catch (error) {

            console.error(
                "Fehler bei /api/me:",
                error
            );


            return res.status(500).json({

                loggedIn: false,

                message:
                    "Benutzer konnte nicht geladen werden."

            });

        }

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


                /*
                   Session-Cookie löschen.
                */

                res.clearCookie(
                    "connect.sid"
                );


                return res.json({

                    success: true

                });

            }
        );

    }
);


/* =====================================================
   SERVER STARTEN
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
            path.join(
                __dirname,
                "nsah.db"
            )
        );

        console.log("");

    }
);
