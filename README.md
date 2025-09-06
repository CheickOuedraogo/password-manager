# 🔐 Gestionnaire de Mots de Passe Sécurisé

Un gestionnaire de mots de passe web moderne et sécurisé avec chiffrement AES-256, conçu pour fonctionner entièrement côté client sans serveur.

##  Fonctionnalités

###  Sécurité Équilibrée

- **Chiffrement AES-256** avec PBKDF2 (100 000 itérations)
- **Mot de passe maître** requis pour accéder aux données
- **Auto-verrouillage** après 15 minutes d'inactivité
- **Re-authentification intelligente** seulement après 2 minutes d'inactivité
- **Stockage local chiffré** - aucune donnée n'est envoyée sur internet
- **Export automatique** lors de la fermeture de la fenêtre

###  Interface Utilisateur

- **Design moderne** en noir/blanc/gris professionnel
- **Navigation par onglets** (Accueil/Paramètres)
- **Responsive design** adapté à tous les écrans
- **Recherche en temps réel** dans tous les champs
- **Tri avancé** par nom, email/username, ou date de création
- **Navigation au clavier** optimisée (touche Entrée)

### 🛠️ Gestion des Mots de Passe

- **Génération automatique** de mots de passe sécurisés
- **Copie en un clic** avec feedback visuel
- **Modification et suppression** des entrées
- **Import/Export JSON** pour la sauvegarde
- **Fusion de fichiers JSON** pour combiner plusieurs sauvegardes
- **Favicons automatiques** pour les sites web

## Installation

1. **Clonez le repository**

   ```bash
   git clone https://github.com/votre-username/password-manager.git
   cd password-manager
   ```

2. **Ouvrez dans un navigateur**

   ```bash
   # Servez les fichiers via un serveur local (recommandé)
   python -m http.server 8000
   # Ou ouvrez directement index.html dans votre navigateur
   ```

3. **Première utilisation**
   - Définissez un mot de passe maître fort
   - Commencez à ajouter vos mots de passe

## Utilisation

### Premier Démarrage

1. Ouvrez l'application dans votre navigateur
2. Créez un **mot de passe maître** sécurisé
3. Votre coffre-fort est maintenant prêt !

### Ajouter un Mot de Passe

1. Cliquez sur "Ajouter un mot de passe"
2. Remplissez les informations (URL, email/username, mot de passe, description)
3. Utilisez le générateur pour créer un mot de passe fort
4. **Navigation rapide** : Utilisez la touche Entrée pour passer au champ suivant
5. Sauvegardez (ou appuyez Entrée sur le dernier champ)

### Recherche et Tri

- **Recherche** : Tapez dans la barre de recherche pour filtrer en temps réel
- **Tri** : Utilisez le menu déroulant pour trier par :
  - Date d'ajout (récent / ancien)
  - Nom de domaine (A-Z / Z-A)
  - Email/Username (A-Z / Z-A)
  - URL complète (A-Z / Z-A)

### Sauvegarde et Restauration

1. **Export automatique** : Activé par défaut, sauvegarde lors de la fermeture
2. **Export manuel** : Cliquez sur "Exporter JSON" dans l'onglet Accueil
3. **Import** : Utilisez "Fusionner JSON" pour importer des données
4. **Paramètres** : Gérez l'export automatique dans l'onglet Paramètres
##  Technologies Utilisées

- **HTML5** - Structure de l'application
- **CSS3** - Design moderne et responsive
- **JavaScript ES6+** - Logique applicative
- **CryptoJS** - Chiffrement AES-256 et PBKDF2
- **LocalStorage** - Stockage local sécurisé

##  Sécurité

### Mesures de Protection
- **Chiffrement client-side** uniquement - aucune donnée transmise
- **Protection anti-brute force** avec blocage temporaire
- **Auto-verrouillage** après 15 minutes d'inactivité
- **Re-authentification intelligente** après 2 minutes d'inactivité seulement
- **Export automatique** pour éviter la perte de données
- **Session unique** pour éviter les accès concurrents

### Configuration de Sécurité Équilibrée
- **5 tentatives** de connexion avant blocage (5 minutes)
- **Mot de passe maître** minimum 8 caractères
- **Session maximale** de 8 heures
- **Presse-papiers** effacé après 30 secondes
- **Mots de passe** masqués après 10 secondes

### Recommandations
- Utilisez un mot de passe maître unique et complexe
- Effectuez des sauvegardes régulières (export automatique activé)
- Gardez l'application à jour
- Gardez l'application à jour
- Utilisez HTTPS en production

## Structure du Projet

```
password-manager/
├── index.html          # Page principale
├── style.css           # Styles CSS
├── script.js           # Logique principale
├── crypto.js           # Fonctions de chiffrement
├── .gitignore          # Fichiers ignorés par Git
└── README.md           # Documentation
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Forkez le projet
2. Créez une branche pour votre fonctionnalité (`git checkout -b feature/nouvelle-fonctionnalite`)
3. Committez vos changements (`git commit -am 'Ajout d'une nouvelle fonctionnalité'`)
4. Poussez vers la branche (`git push origin feature/nouvelle-fonctionnalite`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

##  Fonctionnalités Avancées

### Navigation au Clavier
- **Formulaire d'ajout** : Touche Entrée pour naviguer entre les champs
- **Connexion** : Entrée sur le mot de passe maître pour se connecter
- **Paramètres** : Navigation fluide dans tous les formulaires

### Export Automatique
- **Sauvegarde automatique** lors de la fermeture de la fenêtre
- **Contrôle utilisateur** : Activable/désactivable dans les paramètres
- **Nommage intelligent** : Fichiers horodatés automatiquement

### Interface Optimisée
- **Recherche instantanée** dans tous les champs
- **Tri multi-critères** avec ordre croissant/décroissant
- **Favicons automatiques** pour une identification visuelle rapide
- **Notifications discrètes** pour le feedback utilisateur

## ⚠️ Avertissement

Ce gestionnaire de mots de passe est conçu pour un usage personnel et éducatif. Bien qu'il utilise des pratiques de sécurité robustes avec un chiffrement AES-256, il est recommandé de :
- Faire des sauvegardes régulières (export automatique activé par défaut)
- Tester l'application dans votre environnement
- Utiliser un mot de passe maître fort et unique

## 📞 Support

Si vous rencontrez des problèmes ou avez des questions :
- Ouvrez une [issue](https://github.com/CheickOuedraogo/password-manager/issues)
- Consultez la documentation
- Vérifiez les problèmes existants

---

**Développé avec ❤️ pour la sécurité et la simplicité**
