// main.js - Scripts principaux pour l'application de mitigation DDoS

document.addEventListener('DOMContentLoaded', function() {
    // Initialisation des tooltips Bootstrap
    $('[data-toggle="tooltip"]').tooltip();
    
    // Initialisation des popovers Bootstrap
    $('[data-toggle="popover"]').popover();
    
    // Fermeture automatique des alertes après 5 secondes
    setTimeout(function() {
        $('.alert').alert('close');
    }, 5000);
    
    // Confirmation pour les actions de suppression
    document.querySelectorAll('.btn-delete').forEach(function(button) {
        button.addEventListener('click', function(e) {
            if (!confirm('Êtes-vous sûr de vouloir supprimer cet élément ?')) {
                e.preventDefault();
            }
        });
    });
    
    // Confirmation pour les actions de blocage d'IP
    document.querySelectorAll('.btn-block-ip').forEach(function(button) {
        button.addEventListener('click', function(e) {
            if (!confirm('Êtes-vous sûr de vouloir bloquer cette adresse IP ?')) {
                e.preventDefault();
            }
        });
    });
    
    // Confirmation pour les actions de déblocage d'IP
    document.querySelectorAll('.btn-unblock-ip').forEach(function(button) {
        button.addEventListener('click', function(e) {
            if (!confirm('Êtes-vous sûr de vouloir débloquer cette adresse IP ?')) {
                e.preventDefault();
            }
        });
    });
    
    // Mise à jour automatique des données du tableau de bord
    const dashboardRefresh = document.getElementById('dashboard-refresh');
    if (dashboardRefresh) {
        setInterval(function() {
            fetch('/api/dashboard/stats')
                .then(response => response.json())
                .then(data => {
                    // Mise à jour des statistiques
                    document.getElementById('attacks-count').textContent = data.attacks_count;
                    document.getElementById('blocked-ips-count').textContent = data.blocked_ips_count;
                    document.getElementById('last-attack-time').textContent = data.last_attack_time;
                    
                    // Mise à jour des indicateurs d'état
                    updateStatusIndicator('elasticsearch-status', data.elasticsearch_connected);
                    updateStatusIndicator('fortigate-status', data.fortigate_connected);
                    
                    // Mise à jour du timestamp de rafraîchissement
                    document.getElementById('last-refresh-time').textContent = new Date().toLocaleTimeString();
                })
                .catch(error => console.error('Erreur lors de la mise à jour des données:', error));
        }, 30000); // Rafraîchissement toutes les 30 secondes
    }
    
    // Fonction pour mettre à jour les indicateurs d'état
    function updateStatusIndicator(elementId, isConnected) {
        const element = document.getElementById(elementId);
        if (element) {
            if (isConnected) {
                element.classList.remove('status-offline');
                element.classList.add('status-online');
                element.nextElementSibling.textContent = 'Connecté';
            } else {
                element.classList.remove('status-online');
                element.classList.add('status-offline');
                element.nextElementSibling.textContent = 'Déconnecté';
            }
        }
    }
    
    // Filtrage des tableaux
    const tableFilter = document.getElementById('table-filter');
    if (tableFilter) {
        tableFilter.addEventListener('keyup', function() {
            const filterValue = this.value.toLowerCase();
            const table = document.querySelector('.filterable-table');
            const rows = table.querySelectorAll('tbody tr');
            
            rows.forEach(function(row) {
                const text = row.textContent.toLowerCase();
                if (text.indexOf(filterValue) > -1) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }
    
    // Tri des tableaux
    document.querySelectorAll('.sortable').forEach(function(header) {
        header.addEventListener('click', function() {
            const table = header.closest('table');
            const columnIndex = Array.from(header.parentNode.children).indexOf(header);
            const rows = Array.from(table.querySelectorAll('tbody tr'));
            const isAscending = header.classList.contains('asc');
            
            // Réinitialiser les classes de tri sur tous les en-têtes
            table.querySelectorAll('th').forEach(th => {
                th.classList.remove('asc', 'desc');
            });
            
            // Définir la classe de tri sur l'en-tête actuel
            header.classList.add(isAscending ? 'desc' : 'asc');
            
            // Trier les lignes
            rows.sort(function(a, b) {
                const aValue = a.children[columnIndex].textContent.trim();
                const bValue = b.children[columnIndex].textContent.trim();
                
                // Vérifier si les valeurs sont des nombres
                const aNum = parseFloat(aValue);
                const bNum = parseFloat(bValue);
                
                if (!isNaN(aNum) && !isNaN(bNum)) {
                    return isAscending ? bNum - aNum : aNum - bNum;
                }
                
                // Sinon, trier comme des chaînes
                return isAscending ? 
                    bValue.localeCompare(aValue, 'fr') : 
                    aValue.localeCompare(bValue, 'fr');
            });
            
            // Réorganiser les lignes dans le tableau
            const tbody = table.querySelector('tbody');
            rows.forEach(row => tbody.appendChild(row));
        });
    });
    
    // Gestion des formulaires AJAX
    document.querySelectorAll('.ajax-form').forEach(function(form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(form);
            const url = form.getAttribute('action');
            const method = form.getAttribute('method') || 'POST';
            
            fetch(url, {
                method: method,
                body: formData,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Afficher un message de succès
                    showAlert('success', data.message);
                    
                    // Réinitialiser le formulaire si nécessaire
                    if (data.reset_form) {
                        form.reset();
                    }
                    
                    // Recharger la page si nécessaire
                    if (data.reload) {
                        setTimeout(function() {
                            window.location.reload();
                        }, 1000);
                    }
                } else {
                    // Afficher un message d'erreur
                    showAlert('danger', data.message);
                }
            })
            .catch(error => {
                console.error('Erreur lors de la soumission du formulaire:', error);
                showAlert('danger', 'Une erreur est survenue lors de la soumission du formulaire.');
            });
        });
    });
    
    // Fonction pour afficher une alerte
    function showAlert(type, message) {
        const alertsContainer = document.querySelector('.alerts-container');
        if (alertsContainer) {
            const alert = document.createElement('div');
            alert.className = `alert alert-${type} alert-dismissible fade show`;
            alert.innerHTML = `
                ${message}
                <button type="button" class="close" data-dismiss="alert">
                    <span>&times;</span>
                </button>
            `;
            alertsContainer.appendChild(alert);
            
            // Supprimer l'alerte après 5 secondes
            setTimeout(function() {
                alert.remove();
            }, 5000);
        }
    }
});
