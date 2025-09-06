/**
 * Bibliothèque de chiffrement utilisant CryptoJS
 * Utilise AES-256 avec PBKDF2 pour la dérivation de clé
 */

// Import CryptoJS depuis CDN
const script = document.createElement("script");
script.src =
  "https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.2.0/crypto-js.min.js";
script.integrity =
  "sha512-a+SUDuwNzXDvz4XrIcXHuCf089/iJAoN4lmrXJg18XnduKK6YlDHNRalv4yd1N40OKI80tFidF+rqTFKGPoWFQ==";
script.crossOrigin = "anonymous";
document.head.appendChild(script);

class SecureCrypto {
  constructor() {
    this.algorithm = "AES";
    this.keySize = 256;
    this.iterations = 10000; // Nombre d'itérations PBKDF2
  }

  /**
   * Génère une clé dérivée à partir d'un mot de passe
   * @param {string} password - Mot de passe maître
   * @param {string} salt - Salt pour la dérivation
   * @returns {CryptoJS.lib.WordArray} Clé dérivée
   */
  deriveKey(password, salt) {
    return CryptoJS.PBKDF2(password, salt, {
      keySize: this.keySize / 32,
      iterations: this.iterations,
      hasher: CryptoJS.algo.SHA256,
    });
  }

  /**
   * Chiffre un texte avec AES-256
   * @param {string} plaintext - Texte à chiffrer
   * @param {string} password - Mot de passe maître
   * @returns {string} Texte chiffré encodé en base64
   */
  encrypt(plaintext, password) {
    try {
      // Génère un salt aléatoire
      const salt = CryptoJS.lib.WordArray.random(256 / 8);

      // Génère un IV aléatoire
      const iv = CryptoJS.lib.WordArray.random(128 / 8);

      // Dérive la clé
      const key = this.deriveKey(password, salt);

      // Chiffre le texte
      const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7,
      });

      // Combine salt + iv + données chiffrées
      const combined = salt.concat(iv).concat(encrypted.ciphertext);

      return CryptoJS.enc.Base64.stringify(combined);
    } catch (error) {
      console.error("Erreur de chiffrement:", error);
      throw new Error("Échec du chiffrement");
    }
  }

  /**
   * Déchiffre un texte chiffré avec AES-256
   * @param {string} ciphertext - Texte chiffré en base64
   * @param {string} password - Mot de passe maître
   * @returns {string} Texte déchiffré
   */
  decrypt(ciphertext, password) {
    try {
      // Décode le base64
      const combined = CryptoJS.enc.Base64.parse(ciphertext);

      // Extrait salt (32 bytes), IV (16 bytes) et données chiffrées
      const salt = CryptoJS.lib.WordArray.create(combined.words.slice(0, 8));
      const iv = CryptoJS.lib.WordArray.create(combined.words.slice(8, 12));
      const encrypted = CryptoJS.lib.WordArray.create(combined.words.slice(12));

      // Dérive la clé
      const key = this.deriveKey(password, salt);

      // Déchiffre
      const decrypted = CryptoJS.AES.decrypt(
        CryptoJS.enc.Base64.stringify(encrypted),
        key,
        {
          iv: iv,
          mode: CryptoJS.mode.CBC,
          padding: CryptoJS.pad.Pkcs7,
        }
      );

      const plaintext = decrypted.toString(CryptoJS.enc.Utf8);

      if (!plaintext) {
        throw new Error("Mot de passe incorrect");
      }

      return plaintext;
    } catch (error) {
      console.error("Erreur de déchiffrement:", error);
      throw new Error("Échec du déchiffrement - vérifiez votre mot de passe");
    }
  }

  /**
   * Génère un hash sécurisé d'un mot de passe
   * @param {string} password - Mot de passe à hasher
   * @returns {string} Hash SHA-256
   */
  hashPassword(password) {
    return CryptoJS.SHA256(password).toString();
  }

  /**
   * Génère un mot de passe aléatoire sécurisé
   * @param {number} length - Longueur du mot de passe
   * @param {boolean} includeSymbols - Inclure des symboles spéciaux
   * @returns {string} Mot de passe généré
   */
  generatePassword(length = 16, includeSymbols = true) {
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const numbers = "0123456789";
    const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let charset = lowercase + uppercase + numbers;
    if (includeSymbols) {
      charset += symbols;
    }

    let password = "";
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      password += charset[randomIndex];
    }

    return password;
  }

  /**
   * Vérifie la force d'un mot de passe
   * @param {string} password - Mot de passe à vérifier
   * @returns {object} Score et recommandations
   */
  checkPasswordStrength(password) {
    let score = 0;
    const feedback = [];

    if (password.length >= 8) score += 1;
    else feedback.push("Utilisez au moins 8 caractères");

    if (password.length >= 12) score += 1;

    if (/[a-z]/.test(password)) score += 1;
    else feedback.push("Ajoutez des lettres minuscules");

    if (/[A-Z]/.test(password)) score += 1;
    else feedback.push("Ajoutez des lettres majuscules");

    if (/[0-9]/.test(password)) score += 1;
    else feedback.push("Ajoutez des chiffres");

    if (/[^A-Za-z0-9]/.test(password)) score += 1;
    else feedback.push("Ajoutez des caractères spéciaux");

    const strength = score <= 2 ? "Faible" : score <= 4 ? "Moyen" : "Fort";

    return {
      score,
      strength,
      feedback,
    };
  }
}

// Instance globale
window.secureCrypto = new SecureCrypto();
