// Modules utilisés
const express = require('express'); // Express.js pour gérer les routes et les requêtes HTTP
const mysql2 = require('mysql2'); // MySQL2 pour la connexion à la base de données
const bodyParser = require('body-parser'); // Body-parser pour analyser les corps de requête HTTP
const cors = require('cors'); // CORS pour gérer les autorisations d'accès aux ressources
const bcrypt = require('bcryptjs'); // bcrypt pour le hachage des mots de passe
const https = require('https'); // Pour passer des requêtes HTTP à HTTPS
const axios = require('axios'); // Axios pour effectuer des requêtes HTTP
const fs = require('fs'); // Module 'fs' pour gérer les opérations de fichier
const path = require('path')
const session = require('express-session');
const app = express(); // Création d'une instance d'Express


// Middleware utilisés
app.use(bodyParser.urlencoded({ extended: true })); // Analyse les données encodées dans l'URL
app.use(cors()); // Active CORS pour permettre les requêtes cross-origin
app.use(bodyParser.json()); // Analyse les corps de requête en format JSON
app.use(express.static('public')); // Définit le dossier public pour les fichiers statiques


app.use(session({
    secret: 'test', // Clé secrète pour signer les cookies de session
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 3600000,
        secure: true, // Assurez-vous que le cookie est envoyé uniquement sur HTTPS
        sameSite: 'None' // Définir l'attribut SameSite sur None

    }
}));



// Connexion à la base de données
const db = mysql2.createConnection({
    host: 'localhost',
    user: 'ciel',
    password: 'ciel',
    database: 'testjs',
    port: 3306,
});


// Chemin du fichier JSON
const jsonFilePath = __dirname + '/recu.json';

app.use(express.static(path.join(__dirname, 'public')));


// Connexion à la base de données
db.connect();


// Route racine
app.get('/', (req, res) => {
    res.send('Bonjour, bienvenue sur mon application Node.js !');
});


// Middleware pour vérifier la session
function requireLogin(req, res, next) {
    if (req.session.isLoggedIn) {
        next(); // Continuer vers la route suivante si la session est valide
    } else {
        res.redirect('/connect'); // Rediriger vers la page de connexion sinon
    }
}
// Ajouter des vérifications similaires pour les autres routes protégées (index, sub)


app.get('/connect', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'connect.html'));
});


app.get('/main', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'main.html'));
});


app.get('/index', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});


app.get('/sub', requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'sub.html'));
});


app.post('/login', (req, res) => {
    const { user, password } = req.body;

    // Vérifier les identifiants prédéfinis (admin/admin)
    if (user === 'admin' && password === 'admin') {
        // Créer une session pour l'utilisateur après une connexion réussie
        req.session.user = user;
        req.session.isLoggedIn = true;

        // Renvoyer une réponse réussie
        res.json({ message: 'Connexion réussie', user: user });
    } else {
        // Renvoyer un message d'erreur si les identifiants sont incorrects
        res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });
    }
});


// Route de déconnexion
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Erreur lors de la déconnexion:', err);
            res.status(500).json({ message: 'Erreur lors de la déconnexion' });
        } else {
            res.redirect('/connect');
        }
    });
});



// Route pour l'inscription d'un utilisateur
app.post('/api/signin', async (req, res) => {
    const { users, password, sub } = req.body;

    try {
        // Hachage sécurisé du mot de passe
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);


        const subcon = sub.join(',');

        const query = 'INSERT INTO utilisateurs (users, password, sub) VALUES (?, ?, ?)';
        db.query(query, [users, hashedPassword, subcon], (err, result) => {
            if (err) throw err;
            res.send({ message: 'Inscription réussie', data: result });
        });
    } catch (error) {
        console.error('Error during password hashing:', error);
        res.status(500).json({ message: 'Erreur lors de l\'inscription' });
    }
});


app.post('/api/connexion', async (req, res) => {
    const { user, password } = req.body;
    let ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    // Si l'en-tête X-Forwarded-For contient plusieurs adresses IP (séparées par des virgules), 
    // nous prenons la première adresse IP comme adresse du client.
    if (ipAddress.includes(',')) {
        ipAddress = ipAddress.split(',')[0];
    }

    try {
        // Requête de sélection dans la base de données pour trouver l'utilisateur
        const query = 'SELECT * FROM utilisateurs WHERE users = ?';
        db.query(query, [user], async (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Erreur lors de la connexion' });
            } else if (results.length > 0) {
                const userFromDB = results[0];
                const passwordMatch = await bcrypt.compare(password, userFromDB.password);

                if (passwordMatch) {
                    // Configuration de l'agent HTTPS pour accepter les certificats auto-signés
                    const httpsAgent = new https.Agent({ rejectUnauthorized: false });

                    // Récupération des données depuis une API indépendante
                    axios.get('https://192.168.5.11:3000/api/data', { httpsAgent })
                        .then(response => {
                            // Récupérer les données
                            const jsonData = response.data;

                            // Nettoyer les noms de chaînes en supprimant les espaces inutiles
                            const cleanedChannels = {};
                            for (const channelKey of Object.keys(jsonData)) {
                                const channelData = jsonData[channelKey];
                                const cleanedChannelName = channelData.chaine.trim(); // Supprimer les espaces autour du nom de la chaîne
                                cleanedChannels[channelKey] = { ...channelData, chaine: cleanedChannelName };
                            }

                            // Récupération de la liste des chaînes auxquelles l'utilisateur est abonné
                            const userSubscriptions = userFromDB.sub.split(',');

                            // Filtrer les chaînes en fonction des abonnements de l'utilisateur
                            const filteredChannels = {};
                            for (const sub of userSubscriptions) {
                                const trimmedSub = sub.trim();
                                for (const key in cleanedChannels) {
                                    if (cleanedChannels[key].chaine === trimmedSub) {
                                        filteredChannels[key] = cleanedChannels[key];
                                    }
                                }
                            }

                            // Enregistrement des données filtrées dans le fichier JSON
                            fs.writeFile('recu.json', JSON.stringify(filteredChannels), (err) => {
                                if (err) {
                                    console.error(err);
                                    return res.status(500).json({ message: 'Erreur lors de l\'enregistrement du fichier JSON' });
                                }

                                // Renvoyer les chaînes filtrées comme réponse JSON
                                return res.json(filteredChannels);
                            });
                        })
                        .catch(error => {
                            console.error(error);
                            return res.status(500).json({ message: 'Erreur lors de la récupération des données depuis l\'API indépendante' });
                        });
                } else {
                    return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });
                }
            } else {
                return res.status(401).json({ message: 'Nom d\'utilisateur ou mot de passe incorrect' });
            }
        });
    } catch (error) {
        console.error('Erreur lors de la connexion:', error);
        return res.status(500).json({ message: 'Erreur interne du serveur' });
    }
});


// Route pour tester la disponibilité du fichier JSON
app.get('/api/test', (req, res) => {
    try {
        // Faire une requête GET à l'API externe

        const httpsAgent = new https.Agent({ rejectUnauthorized: false });
        
        axios.get('https://192.168.5.11:3000/api/data', { httpsAgent })
            .then(response => {
                // Récupérer les données
                const jsonData = response.data;

                // Nettoyer les noms de chaînes en supprimant les espaces inutiles
                const cleanedChannels = {};
                for (const channelKey of Object.keys(jsonData)) {
                    const channelData = jsonData[channelKey];
                    const cleanedChannelName = channelData.chaine.trim(); // Supprimer les espaces autour du nom de la chaîne
                    cleanedChannels[channelKey] = { ...channelData, chaine: cleanedChannelName };
                }

                // Enregistrer les données nettoyées dans le fichier JSON
                fs.writeFile('recu.json', JSON.stringify(cleanedChannels), (err) => {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ message: 'Erreur lors de l\'enregistrement du fichier JSON' });
                    }

                    // Envoyer les chaînes nettoyées comme réponse JSON
                    return res.json(cleanedChannels);
                });
            })
            .catch(error => {
                console.error(error);
                return res.status(500).json({ message: 'Erreur lors de la récupération des données depuis l\'API indépendante' });
            });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erreur lors de la récupération des données depuis l\'API indépendante ou lors de l\'enregistrement du fichier JSON' });
    }
});



// Route pour récupérer les abonnés depuis la base de données
app.get('/api/abonnes', (req, res) => {
    const query = 'SELECT users, sub FROM utilisateurs';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Erreur lors de la récupération des abonnés:', err);
            res.status(500).json({ message: 'Erreur lors de la récupération des abonnés' });
        } else {
            res.json(results);
        }
    });
});


// Route pour mettre à jour les abonnements des utilisateurs
app.post('/api/update-abonnements', (req, res) => {
    const updatedAbonnes = req.body;

    console.log('Données reçues pour la mise à jour des abonnements :', updatedAbonnes);

    updatedAbonnes.forEach(abonne => {
        const { user, channels } = abonne;

        // Concaténation des canaux avec une virgule
        const subcon = channels.join(',');
        const query = 'UPDATE utilisateurs SET sub = ? WHERE users = ?';

        // Exécution de la requête de mise à jour dans la base de données
        db.query(query, [subcon, user], (err, result) => {
            if (err) {
                console.error('Erreur lors de la mise à jour des abonnements pour', user, ':', err);
            } else {
                console.log('Abonnements mis à jour avec succès pour', user);
            }
        });
    });

    res.send('Modifications enregistrées avec succès !');
});


const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};


// Création du serveur HTTPS
const server = https.createServer(options, app);


// Écoute du serveur HTTPS sur le port 3001
server.listen(3001, () => {
    console.log(`Serveur démarré sur https://localhost:3001`);
});