// Chiffrement AES-GCM via Web Crypto API.
// Le ciphertext est envoye au serveur, mais la cle (ou le sel PBKDF2)
// reste dans le fragment # de l'URL : le serveur ne peut jamais dechiffrer.

const SeecretCrypto = (function () {
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64ToBuf(b64) {
    const s = b64.replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
    const bin = atob(s + '='.repeat(pad));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }

  async function genRandomKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  async function exportKey(key) {
    return bufToB64(await crypto.subtle.exportKey('raw', key));
  }

  async function importKey(b64) {
    return crypto.subtle.importKey('raw', b64ToBuf(b64), 'AES-GCM', true, ['encrypt', 'decrypt']);
  }

  async function deriveKeyFromPassword(password, salt) {
    const baseKey = await crypto.subtle.importKey(
      'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: salt, iterations: 600000, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Chiffre un texte.
   * Retourne { ciphertext, fragment } :
   *   - ciphertext : a POSTer au serveur (string base64-url)
   *   - fragment   : a placer dans le # de l'URL (string querystring)
   */
  async function encrypt(text, password) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    let key, salt = null, keyB64 = null;

    if (password) {
      salt = crypto.getRandomValues(new Uint8Array(16));
      key = await deriveKeyFromPassword(password, salt);
    } else {
      key = await genRandomKey();
      keyB64 = await exportKey(key);
    }

    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, enc.encode(text));

    // payload (envoye au serveur) = iv (12) || ciphertext
    const payload = new Uint8Array(iv.length + ct.byteLength);
    payload.set(iv, 0);
    payload.set(new Uint8Array(ct), iv.length);

    const params = new URLSearchParams();
    params.set('v', '1');
    params.set('p', password ? '1' : '0');
    if (password) params.set('s', bufToB64(salt.buffer));
    else params.set('k', keyB64);

    return {
      ciphertext: bufToB64(payload.buffer),
      fragment: params.toString()
    };
  }

  /**
   * Dechiffre un ciphertext (recu du serveur) avec les params du fragment.
   * @param {string} ciphertextB64 - retourne par l'API
   * @param {string} hashString    - le window.location.hash (avec ou sans #)
   * @param {string|null} password - le mot de passe utilisateur si requis
   */
  async function decrypt(ciphertextB64, hashString, password) {
    const params = new URLSearchParams(hashString.replace(/^#/, ''));
    if (params.get('v') !== '1') throw new Error('Version non supportee');

    const payload = new Uint8Array(b64ToBuf(ciphertextB64));
    const iv = payload.slice(0, 12);
    const ct = payload.slice(12);

    let key;
    if (params.get('p') === '1') {
      if (!password) throw new Error('Mot de passe requis');
      const salt = new Uint8Array(b64ToBuf(params.get('s')));
      key = await deriveKeyFromPassword(password, salt);
    } else {
      key = await importKey(params.get('k'));
    }

    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
    return dec.decode(plain);
  }

  function isPasswordProtected(hashString) {
    const params = new URLSearchParams(hashString.replace(/^#/, ''));
    return params.get('p') === '1';
  }

  function getId(hashString) {
    const params = new URLSearchParams(hashString.replace(/^#/, ''));
    return params.get('i');
  }

  return { encrypt, decrypt, isPasswordProtected, getId };
})();
