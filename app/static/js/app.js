/**
 * NetMonitor — JavaScript principal
 *
 * Funções utilitárias e auto-refresh de dados via API.
 */

// Utilitário para fazer fetch com CSRF token
function apiFetch(url, options = {}) {
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content
        || document.querySelector('[name="csrf_token"]')?.value
        || '';

    const defaults = {
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
        },
    };

    return fetch(url, { ...defaults, ...options });
}

// Formata data ISO para formato brasileiro
function formatDate(isoString) {
    if (!isoString) return '-';
    const d = new Date(isoString);
    return d.toLocaleString('pt-BR');
}

// O dashboard tem seu próprio auto-refresh ao vivo (fetch + update do DOM),
// definido em templates/main/dashboard.html. O bloco antigo aqui apontava
// para um elemento inexistente (#profileSelector) e nunca rodava — além de
// recarregar a página inteira (reset de gráficos/scroll). Removido.

// Badge de alertas abertos no navbar — atualizado ao vivo em todas as páginas.
(function() {
    const badge = document.getElementById('navAlertBadge');
    if (!badge) return; // usuário não autenticado / navbar ausente

    const profileId = document.body.dataset.activeProfileId || '';
    const url = '/api/alerts/open-count' + (profileId ? `?profile_id=${profileId}` : '');

    function updateBadge() {
        if (document.hidden) return;
        fetch(url)
            .then(r => r.ok ? r.json() : null)
            .then(data => {
                if (!data) return;
                const n = data.open_alerts || 0;
                badge.textContent = n;
                badge.classList.toggle('d-none', n === 0);
            })
            .catch(() => {});
    }

    setInterval(updateBadge, 45000);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) updateBadge();
    });
})();
