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

const db = new Database("nsah.db");


/* =====================================================
   BENUTZER
===================================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        friend_code TEXT UNIQUE
    )
`);


/*
   Falls deine alte users-Tabelle noch keine
   friend_code-Spalte hatte, wird sie hier ergänzt.
*/

try {

    db.prepare(
        "ALTER TABLE users ADD COLUMN friend_code TEXT UNIQUE"
    ).run();

} catch (error) {

    /*
       Wenn die Spalte bereits existiert,
       ist alles in Ordnung.
    */

}


/* =====================================================
   FREUNDSCHAFTEN
===================================================== */

db.exec(`
    CREATE TABLE IF NOT EXISTS friendships (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        user_id INTEGER NOT NULL,

        friend_id INTEGER NOT NULL,

        status TEXT NOT NULL DEFAULT 'pending',

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        UNIQUE(user_id, friend_id),

        FOREIGN KEY(user_id)
            REFERENCES users(id)
            ON DELETE CASCADE,

        FOREIGN KEY(friend_id)
            REFERENCES users(id)
            ON DELETE CASCADE
    )
`);


/* =====================================================
   FEHLENDE FREUNDESCODES ERSTELLEN
===================================================== */

function freundesCodeErstellen() {

    const zeichen =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let code = "NSAH-";

    for (let i = 0; i < 6; i++) {

        code +=
            zeichen[
                Math.floor(
                    Math.random() * zeichen.length
                )
            ];
    }

    return code;
}


function eindeutigenFreundesCodeErstellen() {

    let code;
    let vorhanden = true;

    while (vorhanden) {

        code =
            freundesCodeErstellen();

        const user =
            db.prepare(
                "SELECT id FROM users WHERE friend_code = ?"
            ).get(code);

        vorhanden = !!user;
    }

    return code;
}


/*
   Alte Benutzer bekommen automatisch
   einen Freundescode.
*/

const benutzerOhneCode =
    db.prepare(`
        SELECT id
        FROM users
        WHERE friend_code IS NULL
           OR friend_code = ''
    `).all();


for (const user of benutzerOhneCode) {

    const code =
        eindeutigenFreundesCodeErstellen();

    db.prepare(`
        UPDATE users
        SET friend_code = ?
        WHERE id = ?
    `).run(
        code,
        user.id
    );
}


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
            "NSAH-Geheimer-Schluessel-2026",

        resave: false,

        saveUninitialized: false,

        cookie: {

            httpOnly: true,

            maxAge:
                1000 *
                60 *
                60 *
                24 *
                7
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

            const {
                username,
                email,
                password
            } = req.body;


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


            const passwortHash =
                await bcrypt.hash(
                    password,
                    12
                );


            const friendCode =
                eindeutigenFreundesCodeErstellen();


            const ergebnis =
                db.prepare(`
                    INSERT INTO users
                    (
                        username,
                        email,
                        password,
                        friend_code
                    )
                    VALUES (?, ?, ?, ?)
                `).run(

                    username,

                    email,

                    passwortHash,

                    friendCode

                );


            req.session.userId =
                ergebnis.lastInsertRowid;


            res.json({

                success: true,

                username:
                    username,

                email:
                    email,

                friendCode:
                    friendCode

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

    }
);


/* =====================================================
   ANMELDEN
===================================================== */

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;


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


            /*
               Sicherheitshalber auch bei alten
               Benutzern einen Code erzeugen.
            */

            if (
                !user.friend_code
            ) {

                const neuerCode =
                    eindeutigenFreundesCodeErstellen();


                db.prepare(`
                    UPDATE users
                    SET friend_code = ?
                    WHERE id = ?
                `).run(
                    neuerCode,
                    user.id
                );


                user.friend_code =
                    neuerCode;
            }


            req.session.userId =
                user.id;


            res.json({

                success: true,

                username:
                    user.username,

                email:
                    user.email,

                friendCode:
                    user.friend_code

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

    }
);


/* =====================================================
   AKTUELLER BENUTZER
===================================================== */

app.get(
    "/api/me",
    (req, res) => {

        if (
            !req.session.userId
        ) {

            return res.json({

                loggedIn: false

            });

        }


        const user =
            db.prepare(`
                SELECT
                    id,
                    username,
                    email,
                    friend_code
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

            username:
                user.username,

            email:
                user.email,

            friendCode:
                user.friend_code

        });

    }
);


/* =====================================================
   FREUNDESDATEN
===================================================== */

app.get(
    "/api/friends",
    (req, res) => {

        if (
            !req.session.userId
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Du musst angemeldet sein."

            });

        }


        const userId =
            req.session.userId;


        const user =
            db.prepare(`
                SELECT
                    username,
                    friend_code
                FROM users
                WHERE id = ?
            `).get(userId);


        /*
           Bestätigte Freunde
        */

        const freunde =
            db.prepare(`
                SELECT
                    u.id,
                    u.username,
                    u.email
                FROM friendships f
                JOIN users u
                    ON (
                        CASE
                            WHEN f.user_id = ?
                            THEN u.id = f.friend_id
                            ELSE u.id = f.user_id
                        END
                    )
                WHERE
                    (
                        f.user_id = ?
                        OR f.friend_id = ?
                    )
                    AND f.status = 'accepted'
            `).all(
                userId,
                userId,
                userId
            );


        /*
           Eingehende Anfragen
        */

        const anfragen =
            db.prepare(`
                SELECT
                    f.id,
                    u.username,
                    u.email
                FROM friendships f
                JOIN users u
                    ON u.id = f.user_id
                WHERE
                    f.friend_id = ?
                    AND f.status = 'pending'
            `).all(userId);


        res.json({

            success: true,

            friendCode:
                user.friend_code,

            friends:
                freunde,

            requests:
                anfragen

        });

    }
);


/* =====================================================
   FREUND HINZUFÜGEN
===================================================== */

app.post(
    "/api/friends/add",
    (req, res) => {

        if (
            !req.session.userId
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Du musst angemeldet sein."

            });

        }


        const userId =
            req.session.userId;


        let {
            friendCode
        } = req.body;


        if (
            !friendCode
        ) {

            return res.json({

                success: false,

                message:
                    "Bitte einen Freundescode eingeben."

            });

        }


        friendCode =
            friendCode
                .trim()
                .toUpperCase();


        const friend =
            db.prepare(`
                SELECT
                    id,
                    username
                FROM users
                WHERE friend_code = ?
            `).get(friendCode);


        if (!friend) {

            return res.json({

                success: false,

                message:
                    "Dieser Freundescode wurde nicht gefunden."

            });

        }


        if (
            friend.id === userId
        ) {

            return res.json({

                success: false,

                message:
                    "Du kannst dich nicht selbst hinzufügen."

            });

        }


        /*
           Prüfen, ob bereits eine Verbindung
           in irgendeine Richtung existiert.
        */

        const bestehende =
            db.prepare(`
                SELECT *
                FROM friendships
                WHERE
                    (
                        user_id = ?
                        AND friend_id = ?
                    )
                    OR
                    (
                        user_id = ?
                        AND friend_id = ?
                    )
            `).get(

                userId,
                friend.id,

                friend.id,
                userId

            );


        if (bestehende) {

            if (
                bestehende.status ===
                "accepted"
            ) {

                return res.json({

                    success: false,

                    message:
                        "Ihr seid bereits befreundet."

                });

            }


            if (
                bestehende.status ===
                "pending"
            ) {

                return res.json({

                    success: false,

                    message:
                        "Eine Freundschaftsanfrage existiert bereits."

                });

            }

        }


        db.prepare(`
            INSERT INTO friendships
            (
                user_id,
                friend_id,
                status
            )
            VALUES (?, ?, 'pending')
        `).run(

            userId,

            friend.id

        );


        res.json({

            success: true,

            message:
                "Freundschaftsanfrage gesendet."

        });

    }
);


/* =====================================================
   FREUNDSCHAFTSANFRAGE ANNEHMEN
===================================================== */

app.post(
    "/api/friends/accept",
    (req, res) => {

        if (
            !req.session.userId
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Du musst angemeldet sein."

            });

        }


        const userId =
            req.session.userId;


        const {
            requestId
        } = req.body;


        if (!requestId) {

            return res.json({

                success: false,

                message:
                    "Ungültige Anfrage."

            });

        }


        const anfrage =
            db.prepare(`
                SELECT *
                FROM friendships
                WHERE
                    id = ?
                    AND friend_id = ?
                    AND status = 'pending'
            `).get(

                requestId,

                userId

            );


        if (!anfrage) {

            return res.json({

                success: false,

                message:
                    "Freundschaftsanfrage nicht gefunden."

            });

        }


        db.prepare(`
            UPDATE friendships
            SET status = 'accepted'
            WHERE id = ?
        `).run(
            requestId
        );


        res.json({

            success: true,

            message:
                "Ihr seid jetzt befreundet."

        });

    }
);


/* =====================================================
   FREUNDSCHAFTSANFRAGE ABLEHNEN
===================================================== */

app.post(
    "/api/friends/decline",
    (req, res) => {

        if (
            !req.session.userId
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Du musst angemeldet sein."

            });

        }


        const userId =
            req.session.userId;


        const {
            requestId
        } = req.body;


        db.prepare(`
            DELETE FROM friendships
            WHERE
                id = ?
                AND friend_id = ?
                AND status = 'pending'
        `).run(

            requestId,

            userId

        );


        res.json({

            success: true

        });

    }
);


/* =====================================================
   FREUND ENTFERNEN
===================================================== */

app.post(
    "/api/friends/remove",
    (req, res) => {

        if (
            !req.session.userId
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Du musst angemeldet sein."

            });

        }


        const userId =
            req.session.userId;


        const {
            friendId
        } = req.body;


        db.prepare(`
            DELETE FROM friendships
            WHERE
                (
                    user_id = ?
                    AND friend_id = ?
                )
                OR
                (
                    user_id = ?
                    AND friend_id = ?
                )
        `).run(

            userId,
            friendId,

            friendId,
            userId

        );


        res.json({

            success: true,

            message:
                "Freund entfernt."

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

                    return res.json({

                        success: false,

                        message:
                            "Abmelden fehlgeschlagen."

                    });

                }


                res.json({

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
        console.log("==============================");
        console.log("          NSAH SERVER");
        console.log("==============================");
        console.log("");
        console.log(
            "NSAH läuft auf http://localhost:"
            + PORT
        );
        console.log("");
        console.log(
            "Freundesystem: AKTIV"
        );
        console.log("");

    }
);
