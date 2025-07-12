// Emperor DevSupport VPS Manager Dashboard JavaScript

class EmperorDashboard {
    constructor() {
        this.statsInterval = null;
        this.logsInterval = null;
        this.init();
    }

    init() {
        this.loadStats();
        this.loadActivityLogs();
        this.setupEventListeners();
        this.startAutoRefresh();
    }

    setupEventListeners() {
        // Create user form
        const createUserForm = document.getElementById('createUserForm');
        if (createUserForm) {
            createUserForm.addEventListener('submit', (e) => this.handleCreateUser(e));
        }

        // Create VPN form
        const createVpnForm = document.getElementById('createVpnForm');
        if (createVpnForm) {
            createVpnForm.addEventListener('submit', (e) => this.handleCreateVpn(e));
        }

        // Service toggle buttons
        document.querySelectorAll('[data-service-toggle]').forEach(button => {
            button.addEventListener('click', (e) => this.toggleService(e));
        });

        // Delete user buttons
        document.querySelectorAll('[data-delete-user]').forEach(button => {
            button.addEventListener('click', (e) => this.deleteUser(e));
        });

        // Delete VPN account buttons
        document.querySelectorAll('[data-delete-vpn]').forEach(button => {
            button.addEventListener('click', (e) => this.deleteVpnAccount(e));
        });
    }

    async loadStats() {
        try {
            const response = await fetch('/api/stats');
            const data = await response.json();
            this.updateStatsDisplay(data);
        } catch (error) {
            console.error('Error loading stats:', error);
            this.showNotification('Error loading system statistics', 'error');
        }
    }

    updateStatsDisplay(data) {
        const statsContainer = document.getElementById('stats-container');
        if (!statsContainer) return;

        statsContainer.innerHTML = `
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-microchip"></i>
                    </div>
                    <div class="stat-value">${data.cpu_percent}%</div>
                    <div class="stat-label">CPU Usage</div>
                    <div class="progress mt-2">
                        <div class="progress-bar" style="width: ${data.cpu_percent}%"></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-memory"></i>
                    </div>
                    <div class="stat-value">${(data.memory_used / 1024 / 1024 / 1024).toFixed(1)}GB</div>
                    <div class="stat-label">RAM Used (${data.memory_percent}%)</div>
                    <div class="progress mt-2">
                        <div class="progress-bar" style="width: ${data.memory_percent}%"></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-hdd"></i>
                    </div>
                    <div class="stat-value">${(data.disk_used / 1024 / 1024 / 1024).toFixed(1)}GB</div>
                    <div class="stat-label">Disk Used (${data.disk_percent}%)</div>
                    <div class="progress mt-2">
                        <div class="progress-bar" style="width: ${data.disk_percent}%"></div>
                    </div>
                </div>
            </div>
            <div class="col-md-3 mb-3">
                <div class="stat-card">
                    <div class="stat-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-value">${data.active_users}</div>
                    <div class="stat-label">Active Users</div>
                </div>
            </div>
        `;
    }

    async loadActivityLogs() {
        try {
            const response = await fetch('/api/logs');
            const data = await response.json();
            this.updateLogsDisplay(data.logs);
        } catch (error) {
            console.error('Error loading logs:', error);
        }
    }

    updateLogsDisplay(logs) {
        const tbody = document.querySelector('#activity-table tbody');
        if (!tbody) return;

        tbody.innerHTML = logs.map(log => `
            <tr>
                <td><span class="badge bg-primary">${log.action}</span></td>
                <td>${log.user || 'System'}</td>
                <td>${log.details}</td>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
            </tr>
        `).join('');
    }

    async handleCreateUser(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);

        try {
            const response = await fetch('/create_user', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();

            if (data.success) {
                this.showNotification('User created successfully!', 'success');
                form.reset();
                this.closeModal('createUserModal');
                this.loadStats(); // Refresh stats
            } else {
                this.showNotification('Error: ' + data.error, 'error');
            }
        } catch (error) {
            this.showNotification('Error creating user: ' + error, 'error');
        }
    }

    async handleCreateVpn(e) {
        e.preventDefault();
        const form = e.target;
        const formData = new FormData(form);

        try {
            const response = await fetch('/create_vpn', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();

            if (data.success) {
                this.showNotification('VPN account created successfully!', 'success');
                form.reset();
                this.closeModal('createVpnModal');
                this.loadVpnAccounts();
            } else {
                this.showNotification('Error: ' + data.error, 'error');
            }
        } catch (error) {
            this.showNotification('Error creating VPN account: ' + error, 'error');
        }
    }

    async toggleService(e) {
        const serviceName = e.target.dataset.serviceToggle;
        const button = e.target;

        try {
            button.disabled = true;
            button.innerHTML = '<span class="loading-spinner"></span>';

            const response = await fetch('/api/toggle_service', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ service: serviceName })
            });
            const data = await response.json();

            if (data.success) {
                this.showNotification(`Service ${serviceName} ${data.enabled ? 'enabled' : 'disabled'} successfully!`, 'success');
                location.reload(); // Refresh page to update service status
            } else {
                this.showNotification('Error: ' + data.error, 'error');
            }
        } catch (error) {
            this.showNotification('Error toggling service: ' + error, 'error');
        } finally {
            button.disabled = false;
            button.innerHTML = button.dataset.originalText || 'Toggle';
        }
    }

    async deleteUser(e) {
        const username = e.target.dataset.deleteUser;
        
        if (confirm(`Are you sure you want to delete user "${username}"? This action cannot be undone.`)) {
            try {
                const formData = new FormData();
                formData.append('username', username);
                
                const response = await fetch('/delete_user', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();

                if (data.success) {
                    this.showNotification('User deleted successfully!', 'success');
                    location.reload();
                } else {
                    this.showNotification('Error: ' + data.error, 'error');
                }
            } catch (error) {
                this.showNotification('Error deleting user: ' + error, 'error');
            }
        }
    }

    async deleteVpnAccount(e) {
        const username = e.target.dataset.deleteVpn;
        const serviceType = e.target.dataset.serviceType;
        
        if (confirm(`Are you sure you want to delete ${serviceType} account for "${username}"?`)) {
            try {
                const response = await fetch('/api/delete_vpn_account', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username: username, service_type: serviceType })
                });
                const data = await response.json();

                if (data.success) {
                    this.showNotification('VPN account deleted successfully!', 'success');
                    this.loadVpnAccounts();
                } else {
                    this.showNotification('Error: ' + data.error, 'error');
                }
            } catch (error) {
                this.showNotification('Error deleting VPN account: ' + error, 'error');
            }
        }
    }

    async loadVpnAccounts() {
        try {
            const response = await fetch('/api/vpn_accounts');
            const data = await response.json();
            this.updateVpnAccountsDisplay(data.accounts);
        } catch (error) {
            console.error('Error loading VPN accounts:', error);
        }
    }

    updateVpnAccountsDisplay(accounts) {
        const tbody = document.getElementById('vpn-accounts-table');
        if (!tbody) return;

        tbody.innerHTML = accounts.map(account => `
            <tr>
                <td><strong>${account.username}</strong></td>
                <td>
                    <span class="badge bg-primary">${account.service_type.toUpperCase()}</span>
                </td>
                <td>${account.port}</td>
                <td>
                    <span class="badge bg-${account.is_active ? 'success' : 'danger'}">
                        ${account.is_active ? 'Active' : 'Inactive'}
                    </span>
                </td>
                <td>${new Date(account.created_at).toLocaleDateString()}</td>
                <td>
                    <button class="btn btn-sm btn-danger-neon" data-delete-vpn="${account.username}" data-service-type="${account.service_type}">
                        <i class="fas fa-trash"></i>
                    </button>
                    <button class="btn btn-sm btn-neon" onclick="dashboard.viewConfig('${account.username}', '${account.service_type}')">
                        <i class="fas fa-eye"></i>
                    </button>
                </td>
            </tr>
        `).join('');
    }

    async viewConfig(username, serviceType) {
        try {
            const response = await fetch(`/api/vpn_config/${username}/${serviceType}`);
            const data = await response.json();
            
            if (data.success) {
                this.showConfigModal(username, serviceType, data.config);
            } else {
                this.showNotification('Error: ' + data.error, 'error');
            }
        } catch (error) {
            this.showNotification('Error viewing configuration: ' + error, 'error');
        }
    }

    showConfigModal(username, serviceType, config) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.id = 'configModal';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content" style="background: var(--card-bg); border: 1px solid rgba(0, 255, 65, 0.3);">
                    <div class="modal-header" style="border-bottom: 1px solid rgba(0, 255, 65, 0.2);">
                        <h5 class="modal-title" style="color: var(--neon-green);">
                            <i class="fas fa-cog"></i> Configuration for ${username} (${serviceType.toUpperCase()})
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="terminal-output">
                            <pre>${JSON.stringify(config, null, 2)}</pre>
                        </div>
                    </div>
                    <div class="modal-footer" style="border-top: 1px solid rgba(0, 255, 65, 0.2);">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-neon" onclick="dashboard.copyConfig()">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();
        
        modal.addEventListener('hidden.bs.modal', () => {
            document.body.removeChild(modal);
        });
    }

    copyConfig() {
        const configText = document.querySelector('#configModal pre').textContent;
        navigator.clipboard.writeText(configText).then(() => {
            this.showNotification('Configuration copied to clipboard!', 'success');
        }).catch(() => {
            this.showNotification('Failed to copy configuration', 'error');
        });
    }

    closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            const bootstrapModal = bootstrap.Modal.getInstance(modal);
            if (bootstrapModal) {
                bootstrapModal.hide();
            }
        }
    }

    showNotification(message, type = 'info') {
        const alertClass = type === 'error' ? 'alert-danger' : 
                          type === 'success' ? 'alert-success' : 'alert-info';
        
        const alert = document.createElement('div');
        alert.className = `alert ${alertClass} fade-in-up`;
        alert.innerHTML = message;
        
        const container = document.querySelector('.container-fluid');
        container.insertBefore(alert, container.firstChild);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    }

    startAutoRefresh() {
        // Refresh stats every 30 seconds
        this.statsInterval = setInterval(() => {
            this.loadStats();
        }, 30000);

        // Refresh logs every 60 seconds
        this.logsInterval = setInterval(() => {
            this.loadActivityLogs();
        }, 60000);
    }

    stopAutoRefresh() {
        if (this.statsInterval) {
            clearInterval(this.statsInterval);
        }
        if (this.logsInterval) {
            clearInterval(this.logsInterval);
        }
    }
}

// Initialize dashboard when DOM is loaded
let dashboard;
document.addEventListener('DOMContentLoaded', function() {
    dashboard = new EmperorDashboard();
});

// Cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (dashboard) {
        dashboard.stopAutoRefresh();
    }
}); 