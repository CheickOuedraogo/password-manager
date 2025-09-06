/**
 * Gestionnaire de mots de passe avec chiffrement sécurisé
 */

let passwords = [];
let masterPassword = "";
let isDecrypted = false;
let currentSortBy = "date";
let sortAscending = false;
let editingId = null;
let currentPage = "home";
let autoLockTimer = null;
let lastActivity = Date.now();

// Configuration de sécurité ÉQUILIBRÉE
const SECURITY_CONFIG = {
  AUTO_LOCK_MINUTES: 15, // Verrouillage automatique après 15 minutes d'inactivité
  CLIPBOARD_CLEAR_SECONDS: 30, // Effacer le presse-papiers après 30 secondes
  MAX_FAILED_ATTEMPTS: 5, // Nombre max de tentatives de déchiffrement
  LOCKOUT_MINUTES: 5, // Durée de blocage après échecs (5 minutes)
  PASSWORD_DISPLAY_SECONDS: 10, // Durée d'affichage des mots de passe
  MIN_MASTER_PASSWORD_LENGTH: 8, // Longueur minimale du mot de passe maître
  REQUIRE_STRONG_MASTER_PASSWORD: false, // Ne pas exiger un mot de passe maître ultra-fort
  MAX_SESSION_DURATION_HOURS: 8, // Durée maximale de session (8 heures)
  REQUIRE_REAUTH_FOR_SENSITIVE_ACTIONS: false, // Pas de re-authentification constante
  REAUTH_AFTER_MINUTES: 2, // Re-authentification seulement après 2 minutes d'inactivité
  CLEAR_MEMORY_ON_BLUR: false, // Ne pas effacer quand l'onglet perd le focus
  DISABLE_DEVTOOLS: false, // Ne pas désactiver les outils de développement
  PREVENT_SCREENSHOTS: false, // Ne pas empêcher les captures d'écran
  MAX_CONCURRENT_SESSIONS: 1, // Une seule session active
};

let failedAttempts = 0;
let lockoutUntil = null;
let sessionStartTime = null;
let sessionId = null;
let lastReauthTime = null;
let passwordVisibilityTimers = new Map();
let sensitiveActionInProgress = false;

// Attendre que CryptoJS soit chargé
window.addEventListener("load", () => {
  setTimeout(() => {
    if (typeof CryptoJS === "undefined") {
      console.error("CryptoJS non chargé");
      alert("Erreur: Bibliothèque de chiffrement non disponible");
    } else {
      // Vérifier s'il y a des données sauvegardées
      checkLocalStorage();
      // Initialiser la sécurité
      initSecurity();
    }
  }, 1000);
});

/**
 * Initialise les fonctionnalités de sécurité STRICTES
 */
function initSecurity() {
  // Générer un ID de session unique
  sessionId = generateSessionId();

  // Détection d'activité utilisateur
  [
    "mousedown",
    "mousemove",
    "keypress",
    "scroll",
    "touchstart",
    "click",
  ].forEach((event) => {
    document.addEventListener(event, updateActivity, true);
  });

  // Vérifier le verrouillage automatique toutes les 30 secondes (plus fréquent)
  setInterval(checkAutoLock, 30000);

  // Vérifier la durée maximale de session toutes les minutes
  setInterval(checkSessionDuration, 60000);

  // Effacer les données sensibles lors de la fermeture
  window.addEventListener("beforeunload", (e) => {
    // Export automatique de sauvegarde si des données sont présentes
    if (isDecrypted && passwords.length > 0) {
      autoExportOnClose();
    }
    clearSensitiveData();
    invalidateSession();
  });

  // Verrouillage immédiat si l'onglet devient inactif
  document.addEventListener("visibilitychange", () => {
    if (
      document.hidden &&
      isDecrypted &&
      SECURITY_CONFIG.CLEAR_MEMORY_ON_BLUR
    ) {
      setTimeout(() => {
        if (document.hidden) {
          autoLock();
        }
      }, 5000); // 5 secondes seulement
    }
  });

  // Protection contre les outils de développement
  if (SECURITY_CONFIG.DISABLE_DEVTOOLS) {
    initDevToolsProtection();
  }

  // Protection contre les captures d'écran
  if (SECURITY_CONFIG.PREVENT_SCREENSHOTS) {
    initScreenshotProtection();
  }

  // Détection de tentatives de manipulation du DOM
  initDOMProtection();

  // Protection contre le débogage
  initAntiDebugProtection();
}

/**
 * Génère un ID de session unique
 */
function generateSessionId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

/**
 * Vérifie la durée maximale de session
 */
function checkSessionDuration() {
  if (!sessionStartTime || !isDecrypted) return;

  const sessionDuration = Date.now() - sessionStartTime;
  const maxDuration =
    SECURITY_CONFIG.MAX_SESSION_DURATION_HOURS * 60 * 60 * 1000;

  if (sessionDuration > maxDuration) {
    autoLock();
    showNotification(
      "Session expirée pour sécurité. Reconnectez-vous.",
      "warning"
    );
  }
}

/**
 * Invalide la session actuelle
 */
function invalidateSession() {
  sessionId = null;
  sessionStartTime = null;
  localStorage.removeItem("activeSession");
}

/**
 * Protection contre les outils de développement
 */
function initDevToolsProtection() {
  // Détection d'ouverture des DevTools
  let devtools = { open: false, orientation: null };
  const threshold = 160;

  setInterval(() => {
    if (
      window.outerHeight - window.innerHeight > threshold ||
      window.outerWidth - window.innerWidth > threshold
    ) {
      if (!devtools.open) {
        devtools.open = true;
        if (isDecrypted) {
          autoLock();
          showNotification(
            "Outils de développement détectés. Session verrouillée.",
            "error"
          );
        }
      }
    } else {
      devtools.open = false;
    }
  }, 500);

  // Désactiver le clic droit
  document.addEventListener("contextmenu", (e) => {
    e.preventDefault();
    return false;
  });

  // Désactiver les raccourcis clavier dangereux
  document.addEventListener("keydown", (e) => {
    // F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U
    if (
      e.keyCode === 123 ||
      (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) ||
      (e.ctrlKey && e.keyCode === 85)
    ) {
      e.preventDefault();
      if (isDecrypted) {
        autoLock();
        showNotification(
          "Tentative d'accès aux outils de développement bloquée.",
          "error"
        );
      }
      return false;
    }
  });
}

/**
 * Protection contre les captures d'écran
 */
function initScreenshotProtection() {
  // Ajouter une classe CSS pour empêcher les captures
  document.body.classList.add("no-screenshot");

  // Détecter les tentatives de capture d'écran
  document.addEventListener("keydown", (e) => {
    // Print Screen, Alt+Print Screen
    if (e.keyCode === 44 || (e.altKey && e.keyCode === 44)) {
      e.preventDefault();
      if (isDecrypted) {
        autoLock();
        showNotification(
          "Tentative de capture d'écran détectée. Session verrouillée.",
          "error"
        );
      }
      return false;
    }
  });
}

/**
 * Protection contre la manipulation du DOM
 */
function initDOMProtection() {
  // Observer les modifications du DOM
  const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
      if (mutation.type === "childList" && isDecrypted) {
        // Vérifier si des éléments suspects ont été ajoutés
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === 1) {
            // Element node
            const tagName = node.tagName?.toLowerCase();
            if (
              tagName === "script" ||
              tagName === "iframe" ||
              node.classList?.contains("malicious")
            ) {
              autoLock();
              showNotification(
                "Tentative de manipulation détectée. Session verrouillée.",
                "error"
              );
            }
          }
        });
      }
    });
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

/**
 * Protection anti-débogage
 */
function initAntiDebugProtection() {
  // Détecter les tentatives de débogage
  let start = Date.now();
  debugger;
  if (Date.now() - start > 100) {
    if (isDecrypted) {
      autoLock();
      showNotification("Débogage détecté. Session verrouillée.", "error");
    }
  }

  // Répéter la vérification
  setTimeout(initAntiDebugProtection, 10000);
}

/**
 * Met à jour l'activité utilisateur
 */
function updateActivity() {
  lastActivity = Date.now();
}

/**
 * Vérifie si un verrouillage automatique est nécessaire
 */
function checkAutoLock() {
  if (!isDecrypted) return;

  const inactiveTime = Date.now() - lastActivity;
  const maxInactiveTime = SECURITY_CONFIG.AUTO_LOCK_MINUTES * 60 * 1000;

  if (inactiveTime > maxInactiveTime) {
    autoLock();
  }
}

/**
 * Verrouille automatiquement l'application
 */
function autoLock() {
  if (!isDecrypted) return;

  clearSensitiveData();
  isDecrypted = false;

  // Retourner à l'écran de déchiffrement
  document.getElementById("navTabs").style.display = "none";
  document.getElementById("homePage").style.display = "none";
  document.getElementById("settingsPage").style.display = "none";
  document.getElementById("passwordSection").style.display = "block";

  // Afficher un message
  alert(
    "Session verrouillée pour inactivité. Veuillez saisir votre mot de passe maître."
  );
}

/**
 * Efface les données sensibles de la mémoire de manière STRICTE
 */
function clearSensitiveData() {
  // Effacer le mot de passe maître de la mémoire de manière sécurisée
  if (masterPassword) {
    // Écraser la chaîne avec des caractères aléatoires
    const length = masterPassword.length;
    masterPassword = "";
    for (let i = 0; i < length; i++) {
      masterPassword += String.fromCharCode(Math.floor(Math.random() * 256));
    }
    masterPassword = "";
  }

  // Effacer tous les champs de saisie
  document.querySelectorAll("input").forEach((input) => {
    const length = input.value.length;
    input.value = "";
    // Écraser la mémoire du champ
    for (let i = 0; i < length; i++) {
      input.value += String.fromCharCode(Math.floor(Math.random() * 256));
    }
    input.value = "";
  });

  // Masquer tous les mots de passe affichés
  document.querySelectorAll(".password").forEach((element) => {
    if (element.textContent !== "••••••••") {
      element.textContent = "••••••••";
    }
  });

  // Annuler tous les timers de visibilité
  passwordVisibilityTimers.forEach((timerId) => clearTimeout(timerId));
  passwordVisibilityTimers.clear();

  // Effacer les variables sensibles
  editingId = null;
  sensitiveActionInProgress = false;

  // Forcer le garbage collector si disponible
  if (window.gc) {
    window.gc();
  }

  console.log("Données sensibles effacées de la mémoire");
}

/**
 * Vérifie s'il y a des données dans le localStorage
 */
function checkLocalStorage() {
  const savedData = localStorage.getItem("passwordManager");

  if (savedData) {
    const shouldLoad = confirm(
      "Des mots de passe sauvegardés ont été trouvés.\n" +
        "Voulez-vous les charger ?"
    );

    if (shouldLoad) {
      loadFromLocalStorage();
    } else {
      // Proposer de supprimer les anciennes données
      const shouldDelete = confirm(
        "Voulez-vous supprimer les anciennes données sauvegardées ?"
      );
      if (shouldDelete) {
        localStorage.removeItem("passwordManager");
      }
    }
  }
}

/**
 * Charge les données depuis le localStorage
 */
function loadFromLocalStorage() {
  try {
    const savedData = localStorage.getItem("passwordManager");
    if (!savedData) return;

    const data = JSON.parse(savedData);

    if (data.encrypted && data.passwords) {
      passwords = data.passwords;
      document.getElementById("importSection").style.display = "none";
      document.getElementById("passwordSection").style.display = "block";

      // Modifier le placeholder pour indiquer que c'est depuis localStorage
      const input = document.getElementById("masterPassword");
      input.placeholder =
        "Mot de passe maître pour déchiffrer (données sauvegardées)";
    }
  } catch (error) {
    console.error("Erreur lors du chargement depuis localStorage:", error);
    alert("Erreur lors du chargement des données sauvegardées");
    localStorage.removeItem("passwordManager");
  }
}

let saveTimeout = null;

/**
 * Sauvegarde les données dans le localStorage avec debouncing
 */
function saveToLocalStorage() {
  // Annuler la sauvegarde précédente si elle est en attente
  if (saveTimeout) {
    clearTimeout(saveTimeout);
  }

  // Programmer une nouvelle sauvegarde dans 1 seconde
  saveTimeout = setTimeout(() => {
    try {
      const data = {
        encrypted: true,
        timestamp: new Date().toISOString(),
        passwords: passwords,
        version: "1.0", // Pour la compatibilité future
      };

      const jsonString = JSON.stringify(data);
      localStorage.setItem("passwordManager", jsonString);

      // Vérifier la taille des données
      const sizeKB = Math.round(jsonString.length / 1024);
      console.log(`Données sauvegardées automatiquement (${sizeKB} KB)`);

      // Avertir si les données deviennent trop volumineuses
      if (sizeKB > 5000) {
        // 5MB
        console.warn(
          "Les données deviennent volumineuses. Considérez l'export."
        );
      }
    } catch (error) {
      console.error("Erreur lors de la sauvegarde:", error);

      if (error.name === "QuotaExceededError") {
        showNotification(
          "Espace de stockage insuffisant. Exportez vos données.",
          "error"
        );
      }
    }
  }, 1000);
}

/**
 * Gestion de l'import de fichier JSON
 */
document
  .getElementById("jsonFile")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const data = JSON.parse(e.target.result);

        if (data.encrypted && data.passwords) {
          // Fichier chiffré
          passwords = data.passwords;
          document.getElementById("importSection").style.display = "none";
          document.getElementById("passwordSection").style.display = "block";
        } else if (Array.isArray(data)) {
          // Fichier non chiffré (première importation)
          passwords = data.map((item) => ({
            id: Date.now() + Math.random(),
            url: item.url || "",
            email: item.email || "",
            password: item.password || "",
            description: item.description || "",
            dateAdded: new Date().toISOString(),
            encrypted: false,
          }));

          // Demander le mot de passe maître pour chiffrer
          const master = prompt(
            "Définissez un mot de passe maître pour chiffrer vos données:"
          );
          if (master) {
            masterPassword = master;
            encryptAllPasswords();
            showMainContent();
          }
        } else {
          throw new Error("Format de fichier non reconnu");
        }
      } catch (error) {
        alert("Erreur lors de la lecture du fichier: " + error.message);
      }
    };

    reader.readAsText(file);
  });

/**
 * Gestion de la fusion de fichier JSON
 */
document
  .getElementById("mergeJsonFile")
  .addEventListener("change", function (event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
      try {
        const data = JSON.parse(e.target.result);

        if (data.encrypted && data.passwords) {
          // Vérifier que le mot de passe maître est le même
          if (data.passwords.length > 0) {
            try {
              secureCrypto.decrypt(data.passwords[0].password, masterPassword);

              // Fusionner les données
              const existingUrls = passwords.map((p) => p.url);
              const newPasswords = data.passwords.filter(
                (p) => !existingUrls.includes(p.url)
              );

              passwords = passwords.concat(newPasswords);
              displayPasswords();
              saveToLocalStorage();

              alert(`${newPasswords.length} nouveaux mots de passe ajoutés.`);
            } catch (error) {
              alert(
                "Le fichier JSON utilise un mot de passe maître différent."
              );
            }
          }
        } else {
          alert("Format de fichier non compatible pour la fusion.");
        }
      } catch (error) {
        alert("Erreur lors de la lecture du fichier: " + error.message);
      }
    };

    reader.readAsText(file);
  });

/**
 * Déchiffre tous les mots de passe avec protection anti-brute force STRICTE
 */
function decryptPasswords() {
  // Vérifier si l'utilisateur est en période de blocage
  if (lockoutUntil && Date.now() < lockoutUntil) {
    const remainingTime = Math.ceil((lockoutUntil - Date.now()) / 60000);
    showNotification(
      `Accès bloqué. Réessayez dans ${remainingTime} minute(s).`,
      "error"
    );
    return;
  }

  const masterPass = document.getElementById("masterPassword").value;

  if (!masterPass) {
    showNotification("Veuillez saisir le mot de passe maître", "error");
    return;
  }

  // Vérifier la session active
  if (SECURITY_CONFIG.MAX_CONCURRENT_SESSIONS === 1) {
    const activeSession = localStorage.getItem("activeSession");
    if (activeSession && activeSession !== sessionId) {
      showNotification(
        "Une autre session est déjà active. Fermez-la d'abord.",
        "error"
      );
      return;
    }
  }

  try {
    // Test de déchiffrement sur le premier élément
    if (passwords.length > 0 && passwords[0].encrypted) {
      secureCrypto.decrypt(passwords[0].password, masterPass);
    }

    // Succès : réinitialiser les compteurs
    failedAttempts = 0;
    lockoutUntil = null;

    masterPassword = masterPass;
    isDecrypted = true;
    sessionStartTime = Date.now();
    lastActivity = Date.now();
    lastReauthTime = Date.now(); // Initialiser le temps de re-authentification

    // Marquer la session comme active
    localStorage.setItem("activeSession", sessionId);

    showMainContent();
    showNotification("Authentification réussie", "success");
  } catch (error) {
    failedAttempts++;
    document.getElementById("masterPassword").value = "";

    // Augmenter progressivement le délai de blocage
    const lockoutDuration =
      SECURITY_CONFIG.LOCKOUT_MINUTES * Math.pow(2, failedAttempts - 1);

    if (failedAttempts >= SECURITY_CONFIG.MAX_FAILED_ATTEMPTS) {
      lockoutUntil = Date.now() + lockoutDuration * 60 * 1000;

      // Effacer les données en cas d'attaque persistante
      if (failedAttempts >= 5) {
        localStorage.removeItem("passwordManager");
        showNotification(
          "Trop de tentatives. Données effacées pour sécurité.",
          "error"
        );
      } else {
        showNotification(
          `Accès bloqué pendant ${lockoutDuration} minutes.`,
          "error"
        );
      }
    } else {
      const remaining = SECURITY_CONFIG.MAX_FAILED_ATTEMPTS - failedAttempts;
      showNotification(
        `Mot de passe incorrect. ${remaining} tentative(s) restante(s).`,
        "error"
      );
    }

    // Log de sécurité
    console.warn(
      `Tentative d'authentification échouée ${failedAttempts}/${SECURITY_CONFIG.MAX_FAILED_ATTEMPTS}`
    );
  }
}

/**
 * Chiffre tous les mots de passe
 */
function encryptAllPasswords() {
  passwords = passwords.map((item) => {
    if (!item.encrypted) {
      return {
        ...item,
        password: secureCrypto.encrypt(item.password, masterPassword),
        encrypted: true,
      };
    }
    return item;
  });
}

/**
 * Affiche le contenu principal avec sécurité renforcée
 */
function showMainContent() {
  document.getElementById("passwordSection").style.display = "none";
  document.getElementById("navTabs").style.display = "flex";
  showPage("home");
  displayPasswords();
  updateStats();

  // Activer l'indicateur de sécurité
  updateSecurityIndicator(true);

  // Sauvegarder automatiquement
  saveToLocalStorage();

  // Démarrer la surveillance de sécurité
  startSecurityMonitoring();
}

/**
 * Met à jour l'indicateur de sécurité
 */
function updateSecurityIndicator(secure) {
  const indicator = document.getElementById("securityIndicator");
  if (secure) {
    indicator.textContent = "🔒 Session Sécurisée";
    indicator.classList.add("secure");
  } else {
    indicator.textContent = "⚠️ Session Verrouillée";
    indicator.classList.remove("secure");
  }
}

/**
 * Démarre la surveillance de sécurité continue
 */
function startSecurityMonitoring() {
  // Surveillance des tentatives de manipulation
  setInterval(() => {
    if (isDecrypted) {
      // Vérifier l'intégrité des données critiques
      if (!masterPassword || !sessionId) {
        autoLock();
        showNotification("Intégrité compromise. Session verrouillée.", "error");
      }

      // Vérifier les modifications suspectes du DOM
      const criticalElements = [
        "navTabs",
        "passwordsList",
        "securityIndicator",
      ];
      criticalElements.forEach((id) => {
        if (!document.getElementById(id)) {
          autoLock();
          showNotification(
            "Manipulation du DOM détectée. Session verrouillée.",
            "error"
          );
        }
      });
    }
  }, 5000);
}

/**
 * Verrouillage automatique renforcé
 */
function autoLock() {
  if (!isDecrypted) return;

  // Effacer immédiatement toutes les données sensibles
  clearSensitiveData();
  isDecrypted = false;

  // Invalider la session
  invalidateSession();

  // Retourner à l'écran de déchiffrement
  document.getElementById("navTabs").style.display = "none";
  document.getElementById("homePage").style.display = "none";
  document.getElementById("settingsPage").style.display = "none";
  document.getElementById("passwordSection").style.display = "block";

  // Mettre à jour l'indicateur de sécurité
  updateSecurityIndicator(false);

  // Réinitialiser les compteurs
  lastActivity = Date.now();

  console.warn("Session automatiquement verrouillée pour sécurité");
}

/**
 * Navigation entre les pages
 */
function showPage(page) {
  // Masquer toutes les pages
  document.getElementById("homePage").style.display = "none";
  document.getElementById("settingsPage").style.display = "none";

  // Retirer la classe active de tous les onglets
  document.querySelectorAll(".nav-tab").forEach((tab) => {
    tab.classList.remove("active");
  });

  // Afficher la page demandée
  if (page === "home") {
    document.getElementById("homePage").style.display = "block";
    document.querySelector(".nav-tab:first-child").classList.add("active");
  } else if (page === "settings") {
    document.getElementById("settingsPage").style.display = "block";
    document.querySelector(".nav-tab:last-child").classList.add("active");
    updateStats();
  }

  currentPage = page;
}

/**
 * Met à jour les statistiques
 */
function updateStats() {
  const totalPasswords = passwords.length;
  const oldestDate =
    passwords.length > 0
      ? Math.min(...passwords.map((p) => new Date(p.dateAdded || 0)))
      : null;
  const newestDate =
    passwords.length > 0
      ? Math.max(...passwords.map((p) => new Date(p.dateAdded || 0)))
      : null;

  let statsText = `${totalPasswords} mot(s) de passe enregistré(s)`;

  if (oldestDate && newestDate) {
    const oldest = new Date(oldestDate).toLocaleDateString("fr-FR");
    const newest = new Date(newestDate).toLocaleDateString("fr-FR");
    statsText += `<br>Premier ajout : ${oldest}`;
    if (oldest !== newest) {
      statsText += `<br>Dernier ajout : ${newest}`;
    }
  }

  document.getElementById("statsText").innerHTML = statsText;
  
  // Initialiser le toggle d'export automatique
  initAutoExportToggle();
}

/**
 * Commence sans fichier JSON avec validation stricte
 */
function startFresh() {
  const master = prompt(
    `Définissez un mot de passe maître FORT (min. ${SECURITY_CONFIG.MIN_MASTER_PASSWORD_LENGTH} caractères):`
  );

  if (!master) return;

  // Validation stricte du mot de passe maître
  if (master.length < SECURITY_CONFIG.MIN_MASTER_PASSWORD_LENGTH) {
    alert(
      `Le mot de passe maître doit contenir au moins ${SECURITY_CONFIG.MIN_MASTER_PASSWORD_LENGTH} caractères`
    );
    return;
  }

  if (SECURITY_CONFIG.REQUIRE_STRONG_MASTER_PASSWORD) {
    const strength = secureCrypto.checkPasswordStrength(master);
    if (strength.score < 5) {
      const proceed = confirm(
        `ATTENTION: Mot de passe maître ${strength.strength.toLowerCase()}.\n` +
          `Recommandations: ${strength.feedback.join(", ")}\n\n` +
          `Un mot de passe faible compromet TOUTE la sécurité.\n` +
          `Continuer quand même ? (NON RECOMMANDÉ)`
      );
      if (!proceed) return;
    }
  }

  // Confirmation du mot de passe maître
  const confirmation = prompt("Confirmez le mot de passe maître:");
  if (master !== confirmation) {
    alert("Les mots de passe ne correspondent pas");
    return;
  }

  masterPassword = master;
  passwords = [];
  isDecrypted = true;
  sessionStartTime = Date.now();
  showMainContent();
}

/**
 * Extrait le domaine d'une URL
 */
function extractDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.replace("www.", "");
  } catch {
    return url;
  }
}

/**
 * Obtient l'URL du favicon d'un site
 */
function getFaviconUrl(url) {
  try {
    const urlObj = new URL(url);
    return `https://www.google.com/s2/favicons?domain=${urlObj.hostname}&sz=32`;
  } catch {
    return null;
  }
}

/**
 * Trie les mots de passe
 */
function sortPasswords() {
  const sortBy = document.getElementById("sortSelect").value;
  currentSortBy = sortBy;

  passwords.sort((a, b) => {
    let valueA, valueB;

    switch (sortBy) {
      case "domain":
        valueA = extractDomain(a.url).toLowerCase();
        valueB = extractDomain(b.url).toLowerCase();
        break;
      case "email":
        valueA = (a.email || "").toLowerCase();
        valueB = (b.email || "").toLowerCase();
        break;
      case "url":
        valueA = a.url.toLowerCase();
        valueB = b.url.toLowerCase();
        break;
      case "date":
      default:
        valueA = new Date(a.dateAdded || 0);
        valueB = new Date(b.dateAdded || 0);
        break;
    }

    if (sortBy === "date") {
      return sortAscending ? valueA - valueB : valueB - valueA;
    } else {
      if (sortAscending) {
        return valueA < valueB ? -1 : valueA > valueB ? 1 : 0;
      } else {
        return valueA > valueB ? -1 : valueA < valueB ? 1 : 0;
      }
    }
  });

  displayPasswords();
}

/**
 * Bascule l'ordre de tri
 */
function toggleSortOrder() {
  sortAscending = !sortAscending;
  const btn = document.getElementById("sortOrderBtn");
  btn.textContent = sortAscending ? "↑" : "↓";
  btn.title = sortAscending ? "Ordre croissant" : "Ordre décroissant";
  sortPasswords();
}

/**
 * Filtre les mots de passe en temps réel
 */
function filterPasswords() {
  const searchTerm = document.getElementById("searchInput").value.toLowerCase();
  const items = document.querySelectorAll(".password-item");

  let visibleCount = 0;

  items.forEach((item) => {
    const url = item.querySelector(".url").textContent.toLowerCase();
    const email = item.querySelector(".email")?.textContent.toLowerCase() || "";
    const description =
      item.querySelector(".description")?.title.toLowerCase() || "";

    const matches =
      url.includes(searchTerm) ||
      email.includes(searchTerm) ||
      description.includes(searchTerm);

    if (matches) {
      item.style.display = "flex";
      visibleCount++;
    } else {
      item.style.display = "none";
    }
  });

  // Afficher un message si aucun résultat
  const container = document.getElementById("passwordsList");
  let noResults = container.querySelector(".no-results");

  if (visibleCount === 0 && searchTerm) {
    if (!noResults) {
      noResults = document.createElement("p");
      noResults.className = "no-results no-passwords";
      noResults.textContent = "Aucun résultat trouvé";
      container.appendChild(noResults);
    }
  } else if (noResults) {
    noResults.remove();
  }
}

/**
 * Efface la recherche
 */
function clearSearch() {
  document.getElementById("searchInput").value = "";
  filterPasswords();
}

// Cache pour les favicons
const faviconCache = new Map();

/**
 * Affiche la liste des mots de passe avec optimisations
 */
function displayPasswords() {
  const container = document.getElementById("passwordsList");

  // Utiliser DocumentFragment pour de meilleures performances
  const fragment = document.createDocumentFragment();

  if (passwords.length === 0) {
    container.innerHTML =
      '<p class="no-passwords">Aucun mot de passe enregistré</p>';
    return;
  }

  passwords.forEach((item) => {
    const div = document.createElement("div");
    div.className = "password-item";
    div.dataset.id = item.id;

    const domain = extractDomain(item.url);
    const faviconUrl = getFaviconUrl(item.url);
    const dateFormatted = item.dateAdded
      ? new Date(item.dateAdded).toLocaleDateString("fr-FR")
      : "Date inconnue";

    const description = item.description || "";
    const truncatedDescription =
      description.length > 50
        ? description.substring(0, 50) + "..."
        : description;
    const email = item.email || "";

    // Créer les éléments DOM directement (plus rapide que innerHTML)
    const passwordInfo = document.createElement("div");
    passwordInfo.className = "password-info";

    const siteLogo = document.createElement("div");
    siteLogo.className = "site-logo";

    if (faviconUrl) {
      const img = document.createElement("img");
      img.src = faviconUrl;
      img.alt = domain;
      img.width = 32;
      img.height = 32;
      img.onerror = function () {
        this.style.display = "none";
        this.nextSibling.style.display = "block";
      };

      const fallback = document.createElement("span");
      fallback.textContent = domain.charAt(0).toUpperCase();
      fallback.style.display = "none";

      siteLogo.appendChild(img);
      siteLogo.appendChild(fallback);
    } else {
      siteLogo.textContent = domain.charAt(0).toUpperCase();
    }

    const siteDetails = document.createElement("div");
    siteDetails.className = "site-details";

    const dateDiv = document.createElement("div");
    dateDiv.className = "date-added";
    dateDiv.textContent = `Ajouté le ${dateFormatted}`;

    const urlDiv = document.createElement("div");
    urlDiv.className = "url";
    urlDiv.textContent = item.url;

    if (description) {
      const descSpan = document.createElement("span");
      descSpan.className = "description";
      descSpan.title = description;
      descSpan.textContent = ` (${truncatedDescription})`;
      urlDiv.appendChild(descSpan);
    }

    const passwordDiv = document.createElement("div");
    passwordDiv.className = "password";
    passwordDiv.id = `pass-${item.id}`;
    passwordDiv.textContent = "••••••••";

    siteDetails.appendChild(dateDiv);
    siteDetails.appendChild(urlDiv);

    if (email) {
      const emailDiv = document.createElement("div");
      emailDiv.className = "email";
      emailDiv.textContent = email;
      siteDetails.appendChild(emailDiv);
    }

    siteDetails.appendChild(passwordDiv);

    passwordInfo.appendChild(siteLogo);
    passwordInfo.appendChild(siteDetails);

    // Actions
    const actions = document.createElement("div");
    actions.className = "password-actions";

    const copyBtn = createActionButton(
      "Copier",
      "btn-copy",
      "Copier le mot de passe",
      () => copyPassword(item.id)
    );
    const toggleBtn = createActionButton(
      "Voir",
      "btn-toggle",
      "Afficher/masquer",
      () => togglePassword(item.id)
    );
    const editBtn = createActionButton("Modif", "btn-edit", "Modifier", () =>
      editPassword(item.id)
    );
    const deleteBtn = createActionButton(
      "Suppr",
      "btn-delete",
      "Supprimer",
      () => deletePassword(item.id)
    );

    actions.appendChild(copyBtn);
    actions.appendChild(toggleBtn);
    actions.appendChild(editBtn);
    actions.appendChild(deleteBtn);

    div.appendChild(passwordInfo);
    div.appendChild(actions);
    fragment.appendChild(div);
  });

  // Remplacer tout le contenu en une seule opération
  container.innerHTML = "";
  container.appendChild(fragment);
}

/**
 * Crée un bouton d'action optimisé
 */
function createActionButton(text, className, title, clickHandler) {
  const button = document.createElement("button");
  button.textContent = text;
  button.className = className;
  button.title = title;
  button.addEventListener("click", clickHandler);
  return button;
}

/**
 * Copie un mot de passe dans le presse-papiers avec auto-effacement
 */
async function copyPassword(id) {
  const item = passwords.find((p) => p.id == id);
  if (!item) return;

  try {
    let password = item.password;
    if (item.encrypted) {
      password = secureCrypto.decrypt(password, masterPassword);
    }

    await navigator.clipboard.writeText(password);

    // Feedback visuel amélioré
    const button = document.querySelector(`[data-id="${id}"] .btn-copy`);
    if (button) {
      const originalText = button.textContent;
      const originalColor = button.style.backgroundColor;

      button.textContent = "Copié!";
      button.style.backgroundColor = "#4CAF50";
      button.disabled = true;

      // Programmer l'effacement du presse-papiers
      setTimeout(async () => {
        try {
          await navigator.clipboard.writeText("");
          console.log("Presse-papiers effacé pour sécurité");
        } catch (e) {
          console.log("Impossible d'effacer le presse-papiers");
        }
      }, SECURITY_CONFIG.CLIPBOARD_CLEAR_SECONDS * 1000);

      setTimeout(() => {
        button.textContent = originalText;
        button.style.backgroundColor = originalColor;
        button.disabled = false;
      }, 2000);
    }

    // Notification discrète
    showNotification(
      `Mot de passe copié (effacement automatique dans ${SECURITY_CONFIG.CLIPBOARD_CLEAR_SECONDS}s)`
    );
  } catch (error) {
    // Fallback amélioré
    try {
      let password = item.password;
      if (item.encrypted) {
        password = secureCrypto.decrypt(password, masterPassword);
      }

      const textArea = document.createElement("textarea");
      textArea.value = password;
      textArea.style.position = "fixed";
      textArea.style.left = "-999999px";
      textArea.style.top = "-999999px";
      document.body.appendChild(textArea);
      textArea.focus();
      textArea.select();

      const successful = document.execCommand("copy");
      document.body.removeChild(textArea);

      if (successful) {
        showNotification("Mot de passe copié (méthode de compatibilité)");
      } else {
        throw new Error("Échec de la copie");
      }
    } catch (fallbackError) {
      showNotification(
        "Impossible de copier automatiquement. Copiez manuellement.",
        "error"
      );
      // Afficher temporairement le mot de passe pour copie manuelle
      togglePassword(id);
      setTimeout(() => togglePassword(id), 10000);
    }
  }
}

/**
 * Affiche une notification discrète
 */
function showNotification(message, type = "success") {
  // Supprimer les notifications existantes
  const existing = document.querySelector(".notification");
  if (existing) existing.remove();

  const notification = document.createElement("div");
  notification.className = `notification notification-${type}`;
  notification.textContent = message;

  // Styles inline pour éviter les dépendances CSS
  Object.assign(notification.style, {
    position: "fixed",
    top: "20px",
    right: "20px",
    padding: "12px 20px",
    borderRadius: "6px",
    color: "white",
    fontSize: "14px",
    zIndex: "10000",
    opacity: "0",
    transition: "opacity 0.3s ease",
    backgroundColor: type === "error" ? "#e74c3c" : "#27ae60",
  });

  document.body.appendChild(notification);

  // Animation d'apparition
  setTimeout(() => (notification.style.opacity = "1"), 10);

  // Suppression automatique
  setTimeout(() => {
    notification.style.opacity = "0";
    setTimeout(() => notification.remove(), 300);
  }, 4000);
}

/**
 * Affiche/masque un mot de passe avec limitation de temps STRICTE
 */
function togglePassword(id) {
  const element = document.getElementById(`pass-${id}`);
  const item = passwords.find((p) => p.id == id);

  if (!item) return;

  // Demander une re-authentification seulement après inactivité
  if (element.textContent === "••••••••" && needsReauth()) {
    if (!confirmSensitiveAction()) return;
  }

  if (element.textContent === "••••••••") {
    try {
      let password = item.password;
      if (item.encrypted) {
        password = secureCrypto.decrypt(password, masterPassword);
      }
      element.textContent = password;

      // Masquer automatiquement après le délai configuré
      const timerId = setTimeout(() => {
        element.textContent = "••••••••";
        passwordVisibilityTimers.delete(id);
        showNotification("Mot de passe masqué automatiquement", "info");
      }, SECURITY_CONFIG.PASSWORD_DISPLAY_SECONDS * 1000);

      // Annuler le timer précédent s'il existe
      if (passwordVisibilityTimers.has(id)) {
        clearTimeout(passwordVisibilityTimers.get(id));
      }
      passwordVisibilityTimers.set(id, timerId);

      showNotification(
        `Mot de passe visible pendant ${SECURITY_CONFIG.PASSWORD_DISPLAY_SECONDS}s`,
        "warning"
      );
    } catch (error) {
      element.textContent = "Erreur";
      showNotification("Erreur de déchiffrement", "error");
    }
  } else {
    element.textContent = "••••••••";
    // Annuler le timer si l'utilisateur masque manuellement
    if (passwordVisibilityTimers.has(id)) {
      clearTimeout(passwordVisibilityTimers.get(id));
      passwordVisibilityTimers.delete(id);
    }
  }
}

/**
 * Vérifie si une re-authentification est nécessaire
 */
function needsReauth() {
  if (!lastReauthTime) {
    lastReauthTime = Date.now();
    return false;
  }
  
  const timeSinceReauth = Date.now() - lastReauthTime;
  const reauthThreshold = SECURITY_CONFIG.REAUTH_AFTER_MINUTES * 60 * 1000;
  
  return timeSinceReauth > reauthThreshold;
}

/**
 * Confirme une action sensible avec re-authentification
 */
function confirmSensitiveAction() {
  if (sensitiveActionInProgress) return false;

  sensitiveActionInProgress = true;

  const reauth = prompt(
    "Action sensible. Confirmez votre mot de passe maître:"
  );

  sensitiveActionInProgress = false;

  if (!reauth) return false;

  if (reauth !== masterPassword) {
    showNotification("Mot de passe incorrect. Action annulée.", "error");
    return false;
  }

  // Mettre à jour l'activité et le temps de re-authentification
  lastActivity = Date.now();
  lastReauthTime = Date.now();
  return true;
}

/**
 * Supprime un mot de passe
 */
function deletePassword(id) {
  if (confirm("Êtes-vous sûr de vouloir supprimer ce mot de passe ?")) {
    passwords = passwords.filter((p) => p.id != id);
    displayPasswords();

    // Sauvegarder automatiquement
    saveToLocalStorage();
  }
}

/**
 * Affiche le formulaire d'ajout
 */
function showAddForm() {
  document.getElementById("addForm").style.display = "block";
  document.getElementById("newUrl").focus();
}

/**
 * Masque le formulaire d'ajout
 */
function hideAddForm() {
  document.getElementById("addForm").style.display = "none";
  document.getElementById("newUrl").value = "";
  document.getElementById("newEmail").value = "";
  document.getElementById("newPassword").value = "";
  document.getElementById("newDescription").value = "";
  document.getElementById("formTitle").textContent =
    "Ajouter un nouveau mot de passe";
  document.getElementById("saveBtn").textContent = "Ajouter";
  editingId = null;
}

/**
 * Affiche le formulaire de modification
 */
function editPassword(id) {
  const item = passwords.find((p) => p.id == id);
  if (!item) return;

  editingId = id;

  try {
    let password = item.password;
    if (item.encrypted) {
      password = secureCrypto.decrypt(password, masterPassword);
    }

    document.getElementById("newUrl").value = item.url;
    document.getElementById("newEmail").value = item.email || "";
    document.getElementById("newPassword").value = password;
    document.getElementById("newDescription").value = item.description || "";
    document.getElementById("formTitle").textContent =
      "Modifier le mot de passe";
    document.getElementById("saveBtn").textContent = "Modifier";
    document.getElementById("addForm").style.display = "block";
    document.getElementById("newUrl").focus();
  } catch (error) {
    alert("Erreur lors du déchiffrement pour la modification");
  }
}

/**
 * Sauvegarde un mot de passe (ajout ou modification)
 */
function savePassword() {
  const url = document.getElementById("newUrl").value.trim();
  const email = document.getElementById("newEmail").value.trim();
  const password = document.getElementById("newPassword").value;
  const description = document.getElementById("newDescription").value.trim();

  if (!url || !password) {
    alert("Veuillez remplir au moins l'URL et le mot de passe");
    return;
  }

  // Validation de l'URL
  try {
    new URL(url);
  } catch {
    alert("URL invalide");
    return;
  }

  // Vérification de la force du mot de passe
  const strength = secureCrypto.checkPasswordStrength(password);
  if (strength.score < 3) {
    const proceed = confirm(
      `Mot de passe ${strength.strength.toLowerCase()}.\n` +
        `Recommandations: ${strength.feedback.join(", ")}\n\n` +
        `Continuer quand même ?`
    );
    if (!proceed) return;
  }

  if (editingId) {
    // Modification
    const index = passwords.findIndex((p) => p.id == editingId);
    if (index !== -1) {
      passwords[index] = {
        ...passwords[index],
        url: url,
        email: email,
        password: secureCrypto.encrypt(password, masterPassword),
        description: description,
        encrypted: true,
      };
    }
  } else {
    // Ajout
    const newPassword = {
      id: Date.now() + Math.random(),
      url: url,
      email: email,
      password: secureCrypto.encrypt(password, masterPassword),
      description: description,
      dateAdded: new Date().toISOString(),
      encrypted: true,
    };
    passwords.push(newPassword);
  }

  sortPasswords();
  hideAddForm();
  updateStats();

  // Sauvegarder automatiquement
  saveToLocalStorage();
}

// Garder la fonction addPassword pour compatibilité
function addPassword() {
  savePassword();
}

/**
 * Exporte les mots de passe chiffrés
 */
function exportPasswords() {
  const data = {
    encrypted: true,
    timestamp: new Date().toISOString(),
    passwords: passwords,
  };

  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `passwords_${new Date().toISOString().split("T")[0]}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Export automatique silencieux lors de la fermeture
 */
function autoExportOnClose() {
  try {
    // Vérifier si l'export automatique est activé (par défaut: oui)
    const autoExportEnabled = localStorage.getItem('autoExportOnClose') !== 'false';
    
    if (!autoExportEnabled) {
      return;
    }

    const data = {
      encrypted: true,
      timestamp: new Date().toISOString(),
      passwords: passwords,
      autoBackup: true,
      version: "1.0"
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').split('T');
    a.download = `passwords_auto_backup_${timestamp[0]}_${timestamp[1].split('.')[0]}.json`;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    console.log("Sauvegarde automatique effectuée avant fermeture");
  } catch (error) {
    console.error("Erreur lors de la sauvegarde automatique:", error);
  }
}

/**
 * Gère l'activation/désactivation de l'export automatique
 */
function toggleAutoExport() {
  const toggle = document.getElementById('autoExportToggle');
  const status = document.getElementById('autoExportStatus');
  
  // Vérifier que les éléments existent
  if (!toggle || !status) {
    console.error('Éléments toggle non trouvés');
    return;
  }
  
  const isEnabled = toggle.checked;
  localStorage.setItem('autoExportOnClose', isEnabled.toString());
  
  status.textContent = isEnabled ? 'Activé' : 'Désactivé';
  status.style.color = isEnabled ? '#4CAF50' : '#666';
  
  showNotification(
    `Export automatique ${isEnabled ? 'activé' : 'désactivé'}`,
    'success'
  );
}

/**
 * Initialise l'état du toggle d'export automatique
 */
function initAutoExportToggle() {
  const toggle = document.getElementById('autoExportToggle');
  const status = document.getElementById('autoExportStatus');
  
  // Vérifier que les éléments existent
  if (!toggle || !status) {
    console.warn('Éléments toggle non trouvés');
    return;
  }
  
  // Par défaut activé, sauf si explicitement désactivé
  const isEnabled = localStorage.getItem('autoExportOnClose') !== 'false';
  
  toggle.checked = isEnabled;
  status.textContent = isEnabled ? 'Activé' : 'Désactivé';
  status.style.color = isEnabled ? '#4CAF50' : '#666';
}

/**
 * Gère la navigation au clavier dans le formulaire d'ajout
 */
function handleFormNavigation(event, currentFieldId) {
  if (event.key === 'Enter') {
    event.preventDefault();
    
    const fieldOrder = ['newUrl', 'newEmail', 'newDescription', 'newPassword'];
    const currentIndex = fieldOrder.indexOf(currentFieldId);
    
    if (currentIndex < fieldOrder.length - 1) {
      // Passer au champ suivant
      const nextField = document.getElementById(fieldOrder[currentIndex + 1]);
      nextField.focus();
    } else {
      // Dernier champ, ajouter le mot de passe
      if (editingId) {
        updatePassword();
      } else {
        addPassword();
      }
    }
  }
}

/**
 * Gère la navigation au clavier dans le formulaire de changement de mot de passe maître
 */
function handleMasterPasswordNavigation(event, currentFieldId) {
  if (event.key === 'Enter') {
    event.preventDefault();
    
    const fieldOrder = ['currentMasterPassword', 'newMasterPassword', 'confirmMasterPassword'];
    const currentIndex = fieldOrder.indexOf(currentFieldId);
    
    if (currentIndex < fieldOrder.length - 1) {
      // Passer au champ suivant
      const nextField = document.getElementById(fieldOrder[currentIndex + 1]);
      nextField.focus();
    } else {
      // Dernier champ, changer le mot de passe maître
      changeMasterPassword();
    }
  }
}

// Génération de mot de passe sécurisé
function generateSecurePassword() {
  const password = secureCrypto.generatePassword(16, true);
  document.getElementById("newPassword").value = password;

  // Afficher la force du mot de passe
  const strength = secureCrypto.checkPasswordStrength(password);
  console.log(`Mot de passe généré - Force: ${strength.strength}`);
}

/**
 * Bascule la visibilité d'un champ de mot de passe
 */
function togglePasswordVisibility(inputId) {
  const input = document.getElementById(inputId);
  const toggleButton = input.parentElement.querySelector(".toggle-password");
  const eyeOpen = toggleButton.querySelector(".eye-open");
  const eyeClosed = toggleButton.querySelector(".eye-closed");

  if (input.type === "password") {
    input.type = "text";
    eyeOpen.style.display = "none";
    eyeClosed.style.display = "inline-block";
    toggleButton.title = "Masquer le mot de passe";
  } else {
    input.type = "password";
    eyeOpen.style.display = "inline-block";
    eyeClosed.style.display = "none";
    toggleButton.title = "Afficher le mot de passe";
  }
}

/**
 * Efface les données du localStorage
 */
function clearLocalStorage() {
  const shouldClear = confirm(
    "Êtes-vous sûr de vouloir effacer toutes les données sauvegardées automatiquement ?\n\n" +
      "Cette action est irréversible. Assurez-vous d'avoir exporté vos données si nécessaire."
  );

  if (shouldClear) {
    localStorage.removeItem("passwordManager");
    alert("Données sauvegardées effacées avec succès.");
  }
}

/**
 * Affiche le formulaire de changement de mot de passe maître
 */
function showChangeMasterPasswordForm() {
  document.getElementById("changeMasterForm").style.display = "block";
  document.getElementById("currentMasterPassword").focus();
}

/**
 * Masque le formulaire de changement de mot de passe maître
 */
function hideMasterPasswordForm() {
  document.getElementById("changeMasterForm").style.display = "none";
  document.getElementById("currentMasterPassword").value = "";
  document.getElementById("newMasterPassword").value = "";
  document.getElementById("confirmMasterPassword").value = "";
}

/**
 * Change le mot de passe maître
 */
function changeMasterPassword() {
  const currentPassword = document.getElementById(
    "currentMasterPassword"
  ).value;
  const newPassword = document.getElementById("newMasterPassword").value;
  const confirmPassword = document.getElementById(
    "confirmMasterPassword"
  ).value;

  if (!currentPassword || !newPassword || !confirmPassword) {
    alert("Veuillez remplir tous les champs");
    return;
  }

  // Vérifier le mot de passe actuel
  if (currentPassword !== masterPassword) {
    alert("Mot de passe actuel incorrect");
    return;
  }

  // Vérifier la confirmation
  if (newPassword !== confirmPassword) {
    alert("La confirmation ne correspond pas au nouveau mot de passe");
    return;
  }

  // Vérifier la force du nouveau mot de passe
  const strength = secureCrypto.checkPasswordStrength(newPassword);
  if (strength.score < 4) {
    const proceed = confirm(
      `Nouveau mot de passe ${strength.strength.toLowerCase()}.\n` +
        `Recommandations: ${strength.feedback.join(", ")}\n\n` +
        `Continuer quand même ?`
    );
    if (!proceed) return;
  }

  // Confirmation finale
  const finalConfirm = confirm(
    "Êtes-vous sûr de vouloir changer le mot de passe maître ?\n\n" +
      "Tous vos mots de passe seront re-chiffrés avec le nouveau mot de passe."
  );

  if (!finalConfirm) return;

  try {
    // Déchiffrer tous les mots de passe avec l'ancien mot de passe
    const decryptedPasswords = passwords.map((item) => {
      if (item.encrypted) {
        return {
          ...item,
          password: secureCrypto.decrypt(item.password, masterPassword),
          encrypted: false,
        };
      }
      return item;
    });

    // Mettre à jour le mot de passe maître
    masterPassword = newPassword;

    // Re-chiffrer tous les mots de passe avec le nouveau mot de passe
    passwords = decryptedPasswords.map((item) => ({
      ...item,
      password: secureCrypto.encrypt(item.password, masterPassword),
      encrypted: true,
    }));

    // Sauvegarder
    saveToLocalStorage();

    // Masquer le formulaire et afficher un message de succès
    hideMasterPasswordForm();
    alert("Mot de passe maître modifié avec succès !");
  } catch (error) {
    alert("Erreur lors du changement de mot de passe : " + error.message);
  }
}
