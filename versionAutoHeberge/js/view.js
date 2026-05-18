// Page de visualisation
document.addEventListener('DOMContentLoaded', function () {
  const gateEl = document.getElementById('gate');
  const revealBtn = document.getElementById('reveal-btn');
  const robotCheck = document.getElementById('not-robot-check');
  const loadingEl = document.getElementById('loading');
  const errorEl = document.getElementById('error');
  const secretEl = document.getElementById('secret-content');
  const secretBox = document.getElementById('secret-box');
  const copyBtn = document.getElementById('copy-secret-btn');

  function show(el) { el.style.display = 'block'; }
  function hide(el) { el.style.display = 'none'; }

  function showError(message) {
    hide(loadingEl); hide(secretBox); hide(gateEl);
    errorEl.textContent = message;
    show(errorEl);
  }

  function showSecret(text) {
    hide(loadingEl); hide(errorEl); hide(gateEl);
    secretEl.textContent = text;
    show(secretBox);
  }

  const hash = window.location.hash;
  if (!hash || hash.length < 2) {
    showError('Aucun secret à afficher. Le lien semble incomplet.');
    return;
  }

  const id = SeecretCrypto.getId(hash);
  if (!id) {
    showError('Identifiant manquant dans le lien.');
    return;
  }

  robotCheck.addEventListener('change', function () {
    revealBtn.disabled = !robotCheck.checked;
  });

  async function fetchCiphertext() {
    const resp = await fetch('api.php?id=' + encodeURIComponent(id), { method: 'GET' });
    if (resp.status === 404) throw new Error('Secret introuvable, expiré ou déjà lu.');
    if (!resp.ok) throw new Error('Erreur serveur (' + resp.status + ').');
    const data = await resp.json();
    return data.ciphertext;
  }

  revealBtn.addEventListener('click', async function () {
    if (!robotCheck.checked) return;

    hide(gateEl);
    show(loadingEl);

    let password = null;
    if (SeecretCrypto.isPasswordProtected(hash)) {
      hide(loadingEl);
      const { value } = await Swal.fire({
        title: 'Mot de passe requis',
        input: 'password',
        inputPlaceholder: 'Entrez le mot de passe',
        showCancelButton: true,
        confirmButtonText: 'Déverrouiller',
        cancelButtonText: 'Annuler',
        inputValidator: (v) => !v && 'Mot de passe requis'
      });
      if (!value) { showError('Lecture annulée. Le secret n\'a pas été récupéré.'); return; }
      password = value;
      show(loadingEl);
    }

    // ATTENTION : ce GET detruit le secret cote serveur.
    // Si le password est faux, on a "consomme" le secret pour rien.
    let ciphertext;
    try {
      ciphertext = await fetchCiphertext();
    } catch (e) {
      showError(e.message);
      return;
    }

    try {
      const text = await SeecretCrypto.decrypt(ciphertext, hash, password);
      // Privacy : retire la cle de l'URL/historique apres lecture reussie.
      // Le secret est deja detruit cote serveur, l'URL n'est plus utile.
      try { history.replaceState(null, '', window.location.pathname); } catch (e) {}
      showSecret(text);
    } catch (e) {
      showError('Déchiffrement impossible (mot de passe erroné ou lien corrompu). Le secret a été détruit côté serveur.');
    }
  });

  copyBtn.addEventListener('click', async function () {
    try {
      await navigator.clipboard.writeText(secretEl.textContent);
      copyBtn.textContent = 'Copié !';
      setTimeout(function () { copyBtn.textContent = 'Copier'; }, 1500);
    } catch (e) {
      const range = document.createRange();
      range.selectNodeContents(secretEl);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      document.execCommand('copy');
    }
  });
});
