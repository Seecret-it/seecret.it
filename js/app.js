// Page de creation
document.addEventListener('DOMContentLoaded', function () {
  const form = document.getElementById('create-form');
  const secretInput = document.getElementById('secret-input');
  const passwordInput = document.getElementById('password-input');
  const expiresSelect = document.getElementById('expires-select');
  const submitBtn = document.getElementById('submit-btn');
  const charCounter = document.getElementById('char-counter');
  const MAX_LEN = 10000;

  secretInput.addEventListener('input', function () {
    charCounter.textContent = secretInput.value.length + ' / ' + MAX_LEN;
  });

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));
  }

  function showLinkModal(url, expiresIn) {
    const exptxt = formatDuration(expiresIn);
    Swal.fire({
      icon: 'success',
      title: 'Lien créé',
      html:
        '<p style="color:#666; font-size:0.9rem; margin-bottom:1rem;">Le lien expire dans <strong>' + exptxt + '</strong> et sera détruit à la première lecture.</p>' +
        '<input type="text" id="swal-link" class="swal2-input" readonly value="' + escapeHtml(url) + '" ' +
        'style="font-family:ui-monospace,Menlo,monospace; font-size:0.8rem; word-break:break-all; width:100%; margin:0;">',
      showCancelButton: true,
      confirmButtonText: 'Copier le lien',
      cancelButtonText: 'Nouveau secret',
      reverseButtons: true,
      focusConfirm: false,
      didOpen: () => {
        const input = document.getElementById('swal-link');
        input.addEventListener('focus', () => input.select());
        setTimeout(() => input.select(), 100);
      },
      preConfirm: async () => {
        const input = document.getElementById('swal-link');
        try {
          await navigator.clipboard.writeText(input.value);
        } catch (e) {
          input.select();
          document.execCommand('copy');
        }
        return true;
      }
    }).then((result) => {
      if (result.isConfirmed) {
        Swal.fire({ icon: 'success', title: 'Copié !', timer: 1200, showConfirmButton: false });
        resetForm();
      } else if (result.dismiss === Swal.DismissReason.cancel) {
        resetForm();
      }
    });
  }

  function formatDuration(seconds) {
    if (seconds < 3600) return Math.round(seconds / 60) + ' min';
    if (seconds < 86400) return Math.round(seconds / 3600) + ' h';
    return Math.round(seconds / 86400) + ' jours';
  }

  function resetForm() {
    secretInput.value = '';
    passwordInput.value = '';
    charCounter.textContent = '0 / ' + MAX_LEN;
    secretInput.focus();
  }

  function setLoading(loading) {
    submitBtn.disabled = loading;
    submitBtn.textContent = loading ? 'Chiffrement…' : 'Créer le lien';
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    const text = secretInput.value.trim();
    if (!text) {
      Swal.fire({ icon: 'warning', title: 'Champ vide', text: 'Saisissez le contenu du secret.' });
      return;
    }
    if (text.length > MAX_LEN) {
      Swal.fire({ icon: 'error', title: 'Trop long', text: 'Maximum ' + MAX_LEN + ' caractères.' });
      return;
    }

    const password = passwordInput.value;
    const expiresIn = parseInt(expiresSelect.value, 10);

    setLoading(true);
    try {
      const { ciphertext, fragment } = await SeecretCrypto.encrypt(text, password);

      const resp = await fetch('api.php', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ciphertext: ciphertext, expires_in: expiresIn })
      });

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({ error: 'Erreur serveur' }));
        throw new Error(err.error || 'Erreur serveur');
      }
      const { id } = await resp.json();

      const base = window.location.href.split('/').slice(0, -1).join('/');
      const url = base + '/view.html#i=' + encodeURIComponent(id) + '&' + fragment;
      showLinkModal(url, expiresIn);
    } catch (err) {
      Swal.fire({ icon: 'error', title: 'Erreur', text: err.message });
    } finally {
      setLoading(false);
    }
  });
});
