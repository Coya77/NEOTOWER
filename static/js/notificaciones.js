class NotificacionesManager {
    constructor() {
        this.notificationBell = document.getElementById('notificationBell');
        this.notificationCount = document.getElementById('notificationCount');
        this.notificationDropdown = document.getElementById('notificationDropdown');
        this.pollingInterval = null;
        this.isOpen = false;
        
        this.init();
    }
    
    init() {
        if (!this.notificationBell) return;
        
        // Cargar notificaciones al iniciar
        this.cargarNotificaciones();
        
        // Event listeners
        this.notificationBell.addEventListener('click', (e) => {
            e.preventDefault();
            this.toggleDropdown();
        });
        
        // Cerrar dropdown al hacer click fuera
        document.addEventListener('click', (e) => {
            if (!this.notificationBell.contains(e.target) && 
                !this.notificationDropdown.contains(e.target)) {
                this.cerrarDropdown();
            }
        });
        
        // Polling cada 30 segundos
        this.pollingInterval = setInterval(() => {
            this.cargarNotificaciones();
        }, 30000);
    }
    
    toggleDropdown() {
        if (this.isOpen) {
            this.cerrarDropdown();
        } else {
            this.abrirDropdown();
        }
    }
    
    abrirDropdown() {
        this.isOpen = true;
        this.notificationDropdown.classList.add('show');
        this.cargarNotificaciones(); // Recargar al abrir
    }
    
    cerrarDropdown() {
        this.isOpen = false;
        this.notificationDropdown.classList.remove('show');
    }
    
    async cargarNotificaciones() {
        try {
            const response = await fetch('/notificaciones/obtener');
            const data = await response.json();
            
            if (data.error) {
                console.error('Error cargando notificaciones:', data.error);
                return;
            }
            
            this.actualizarContador(data.total_no_leidas);
            this.renderNotificaciones(data.notificaciones);
            
        } catch (error) {
            console.error('Error cargando notificaciones:', error);
        }
    }
    
    actualizarContador(totalNoLeidas) {
        if (this.notificationCount) {
            if (totalNoLeidas > 0) {
                this.notificationCount.textContent = totalNoLeidas;
                this.notificationCount.classList.add('bg-danger');
                this.notificationCount.style.display = 'block';
                
                // Efecto de vibración si hay notificaciones nuevas
                if (totalNoLeidas > 0) {
                    this.notificationBell.classList.add('vibrate');
                    setTimeout(() => {
                        this.notificationBell.classList.remove('vibrate');
                    }, 500);
                }
            } else {
                this.notificationCount.style.display = 'none';
            }
        }
    }
    
    renderNotificaciones(notificaciones) {
        const container = this.notificationDropdown.querySelector('.notification-list');
        if (!container) return;
        
        if (notificaciones.length === 0) {
            container.innerHTML = `
                <div class="text-center p-3 text-muted">
                    <i class="bi bi-bell-slash fs-2"></i>
                    <p class="mb-0 mt-2">No hay notificaciones</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = notificaciones.map(notif => `
            <div class="notification-item ${notif.leida ? 'read' : 'unread'}" 
                 data-id="${notif.id_notificacion}"
                 data-type="${notif.tipo}"
                 data-reference="${notif.id_referencia || ''}">
                <div class="d-flex align-items-start">
                    <div class="notification-icon me-3">
                        ${this.getIconoPorTipo(notif.tipo)}
                    </div>
                    <div class="flex-grow-1">
                        <h6 class="mb-1">${this.escapeHtml(notif.titulo)}</h6>
                        <p class="mb-1 small">${this.escapeHtml(notif.mensaje)}</p>
                        <small class="text-muted">${this.formatearFecha(notif.fecha_creacion)}</small>
                    </div>
                    ${!notif.leida ? '<span class="badge bg-primary ms-2">Nuevo</span>' : ''}
                </div>
            </div>
        `).join('');
        
        // Agregar event listeners a las notificaciones
        container.querySelectorAll('.notification-item.unread').forEach(item => {
            item.addEventListener('click', () => {
                this.procesarClickNotificacion(item);
            });
        });
        
        // Botón marcar todas como leídas
        const footer = this.notificationDropdown.querySelector('.notification-footer');
        if (footer && notificaciones.some(n => !n.leida)) {
            footer.innerHTML = `
                <button class="btn btn-sm btn-outline-primary w-100" id="markAllRead">
                    <i class="bi bi-check2-all me-1"></i>Marcar todas como leídas
                </button>
            `;
            
            document.getElementById('markAllRead').addEventListener('click', () => {
                this.marcarTodasLeidas();
            });
        }
    }
    
    async procesarClickNotificacion(item) {
        const idNotificacion = item.dataset.id;
        
        try {
            const response = await fetch(`/notificaciones/marcar-leida/${idNotificacion}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                // Cerrar el dropdown
                this.cerrarDropdown();
                
                // Redirigir a la URL especificada
                if (data.redirect_url) {
                    window.location.href = data.redirect_url;
                }
            } else {
                console.error('Error procesando notificación:', data.error);
            }
        } catch (error) {
            console.error('Error procesando notificación:', error);
        }
    }
    
    async marcarTodasLeidas() {
        try {
            const response = await fetch('/notificaciones/marcar-todas-leidas', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            });
            
            if (response.ok) {
                this.cargarNotificaciones();
            }
        } catch (error) {
            console.error('Error marcando todas como leídas:', error);
        }
    }
    
    getIconoPorTipo(tipo) {
        const iconos = {
            'anuncio': '<i class="bi bi-megaphone text-primary"></i>',
            'pago': '<i class="bi bi-credit-card text-success"></i>',
            'incidente': '<i class="bi bi-exclamation-triangle text-warning"></i>',
            'default': '<i class="bi bi-bell text-secondary"></i>'
        };
        return iconos[tipo] || iconos.default;
    }
    
    formatearFecha(fechaString) {
        const fecha = new Date(fechaString);
        const ahora = new Date();
        const diffMs = ahora - fecha;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Ahora mismo';
        if (diffMins < 60) return `Hace ${diffMins} min`;
        if (diffHours < 24) return `Hace ${diffHours} h`;
        if (diffDays < 7) return `Hace ${diffDays} d`;
        
        return fecha.toLocaleDateString();
    }
    
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Inicializar cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', function() {
    new NotificacionesManager();
});