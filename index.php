<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Enterprise Dashboard</title>
    <style>
        :root {
            --bg-dark: #0f172a;
            --bg-panel: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent: #3b82f6;
            --danger: #ef4444;
            --success: #10b981;
            --border: #334155;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
        }

        body {
            background-color: var(--bg-dark);
            color: var(--text-primary);
            height: 100vh;
            display: flex;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 260px;
            background-color: var(--bg-panel);
            border-right: 1px solid var(--border);
            display: flex;
            flex-direction: column;
            padding: 1.5rem;
        }

        .brand {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
            margin-bottom: 2rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .nav-item {
            padding: 0.75rem 1rem;
            color: var(--text-secondary);
            cursor: pointer;
            border-radius: 0.5rem;
            margin-bottom: 0.5rem;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .nav-item:hover, .nav-item.active {
            background-color: rgba(59, 130, 246, 0.1);
            color: var(--accent);
        }

        /* Main Content */
        .main {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow-y: auto;
        }

        .header {
            height: 70px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 2rem;
        }

        .user-profile {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .avatar {
            width: 36px;
            height: 36px;
            background-color: var(--accent);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
        }

        .content-area {
            padding: 2rem;
        }

        /* Panels */
        .panel {
            background-color: var(--bg-panel);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .panel.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        h2 { margin-bottom: 1.5rem; font-size: 1.25rem; font-weight: 600; }
        
        .grid-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background-color: rgba(255,255,255,0.03);
            padding: 1.25rem;
            border-radius: 0.5rem;
            border: 1px solid var(--border);
        }

        .stat-value {
            font-size: 1.5rem;
            font-weight: 700;
            margin-top: 0.5rem;
        }

        .stat-label { color: var(--text-secondary); font-size: 0.875rem; }

        /* Forms */
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: var(--text-secondary); font-size: 0.875rem; }
        input {
            width: 100%;
            padding: 0.75rem;
            background-color: var(--bg-dark);
            border: 1px solid var(--border);
            border-radius: 0.375rem;
            color: var(--text-primary);
        }
        
        button {
            background-color: var(--accent);
            color: white;
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 0.375rem;
            cursor: pointer;
            font-weight: 500;
            transition: opacity 0.2s;
        }
        
        button:hover { opacity: 0.9; }
        button.secondary { background-color: transparent; border: 1px solid var(--border); }
        button.danger { background-color: var(--danger); }

        .terminal {
            background-color: #000;
            padding: 1rem;
            border-radius: 0.5rem;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
            color: #10b981;
            margin-top: 1rem;
            min-height: 100px;
            white-space: pre-wrap;
        }

        .hidden { display: none !important; }
    </style>
</head>
<body>

    <!-- Login Screen -->
    <div id="login-overlay" style="position: fixed; inset: 0; background: var(--bg-dark); z-index: 50; display: flex; align-items: center; justify-content: center;">
        <div class="panel active" style="width: 400px;">
            <div style="text-align: center; margin-bottom: 2rem;">
                <h1 style="color: var(--accent); margin-bottom: 0.5rem;">Nexus Enterprise</h1>
                <p style="color: var(--text-secondary);">Secure Access Portal</p>
            </div>
            <div class="form-group">
                <label>Employee ID</label>
                <input type="text" id="login-id" value="guest_user" readonly>
            </div>
            <button onclick="app.login()" style="width: 100%;">Authenticate</button>
        </div>
    </div>

    <!-- App Interface -->
    <div class="sidebar">
        <div class="brand">
            <span>◆</span> Nexus
        </div>
        <div class="nav-item active" onclick="app.nav('dashboard')">
            <span>📊</span> Dashboard
        </div>
        <div class="nav-item" onclick="app.nav('finance')">
            <span>💳</span> Finance
        </div>
        <!-- Admin Navigation (Restricted) -->
        <div class="nav-item" id="nav-admin" onclick="app.nav('admin')" style="display: none;">
            <span>🛡️</span> Administration
        </div>
        <div class="nav-item" onclick="app.nav('settings')">
            <span>⚙️</span> System Config
        </div>
    </div>

    <div class="main">
        <div class="header">
            <div style="font-weight: 600;">System Status: <span style="color: var(--success);">Operational</span></div>
            <div class="user-profile">
                <span id="user-role-display" style="color: var(--text-secondary); font-size: 0.875rem;">Role: Guest</span>
                <div class="avatar">G</div>
            </div>
        </div>

        <div class="content-area">
            
            <div id="finance-panel" class="panel">
                <h2>Financial Operations</h2>
                <div class="grid-stats">
                    <div class="stat-card">
                        <div class="stat-label">Checking Account</div>
                        <div class="stat-value" id="balance-checking">0.00</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Investment Vault</div>
                        <div class="stat-value" id="balance-vault">0.00</div>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 2rem;">
                    <div>
                        <h3 style="margin-bottom: 1rem; font-size: 1rem; color: var(--text-secondary);">Transfer Funds</h3>
                        <div class="form-group">
                            <label>Amount (Credits)</label>
                            <input type="number" id="transfer-amount" value="100">
                        </div>
                        <button onclick="app.transfer()">Execute Transfer</button>
                    </div>
                    <div>
                        <h3 style="margin-bottom: 1rem; font-size: 1rem; color: var(--text-secondary);">Marketplace</h3>
                        <div class="stat-card" style="margin-bottom: 1rem;">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <span>Premium Audit Report</span>
                                <span style="font-weight: bold;">200 Credits</span>
                            </div>
                            <button onclick="app.buyReport()" class="secondary" style="width: 100%; margin-top: 1rem;">Purchase</button>
                        </div>
                    </div>
                </div>
                <div id="finance-log" class="terminal">Waiting for transaction...</div>
            </div>

            <div id="dashboard-panel" class="panel active">
                <h2>System Overview</h2>
                <div class="grid-stats">
                    <div class="stat-card">
                        <div class="stat-label">Active Nodes</div>
                        <div class="stat-value">142</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">Uptime</div>
                        <div class="stat-value">99.99%</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-label">System Mode</div>
                        <div class="stat-value" style="color: var(--accent);">ReadOnly</div>
                    </div>
                </div>
            </div>

            <div id="admin-panel" class="panel">
                <h2>Administration Console</h2>
                <div style="border: 1px solid var(--border); border-radius: 0.5rem; overflow: hidden; margin-bottom: 2rem;">
                    <div style="background: rgba(0,0,0,0.3); padding: 0.75rem 1rem; font-weight: 600; border-bottom: 1px solid var(--border);">
                        System Activity Logs (Confidential)
                    </div>
                    <div id="admin-logs-view" style="padding: 1rem; font-family: monospace; font-size: 0.875rem; color: var(--text-secondary); max-height: 200px; overflow-y: auto;">
                        <span class="loading">Loading stream...</span>
                    </div>
                </div>

                <hr style="border: 0; border-top: 1px solid var(--border); margin: 2rem 0;">

                <h3>Elevated Operations</h3>
                <p style="margin-bottom: 1rem; color: var(--text-secondary);">Administrative override controls.</p>
                
                <button onclick="app.getAdminData()" class="danger">Execute SysAdmin Protocol (JWT Check)</button>
                <div id="admin-log" class="terminal" style="margin-top: 1rem;">Waiting for command...</div>
            </div>

            <div id="settings-panel" class="panel">
                <h2>System Configuration</h2>
                <p style="margin-bottom: 1rem;">Key Reassembly Module v2.1</p>
                
                <div class="form-group">
                    <label>Master Configuration Key</label>
                    <input type="text" id="master-key" placeholder="Enter N-Fragment Sequence">
                </div>

                <button onclick="app.verifyConfig()">Verify Configuration</button>
                <div id="config-log" class="terminal">System Ready.</div>
            </div>

        </div>
    </div>

    <script>
        const app = {
            state: {
                token: localStorage.getItem('nexus_token'),
                role: 'guest'
            },

            init() {
                localStorage.removeItem('cosmic_token');
                localStorage.removeItem('archive_token');
                
                if (this.state.token) {
                    document.getElementById('login-overlay').style.display = 'none';
                    this.loadProfile();
                } else {
                    this.login();
                }
            },

            async login() {
                const res = await fetch('api.php?action=login', { method: 'POST' });
                const data = await res.json();
                if (data.token) {
                    localStorage.setItem('nexus_token', data.token);
                    this.state.token = data.token;
                    document.getElementById('login-overlay').style.display = 'none';
                    this.loadProfile();
                }
            },

            loadProfile() {
                try {
                    const payload = JSON.parse(atob(this.state.token.split('.')[1]));
                    this.state.role = payload.role || 'guest';
                    document.getElementById('user-role-display').innerText = 'Role: ' + this.state.role;
                    
                    if (this.state.role === 'admin') {
                        document.getElementById('nav-admin').style.display = 'flex';
                    }
                } catch (e) { console.error('Token parse user', e); }
            },

            nav(panelId) {
                document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
                document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
                
                const panel = document.getElementById(panelId + '-panel');
                if (panel) panel.classList.add('active');
                
                const navItem = event ? event.target.closest('.nav-item') : null;
                if (navItem) navItem.classList.add('active');

                if(panelId === 'finance') this.refreshFinance();
                if(panelId === 'admin') this.loadAdminLogs(); 
            },

            async loadAdminLogs() {
                const view = document.getElementById('admin-logs-view');
                view.innerHTML = '<span style="color:var(--accent)">Establishing secure connection...</span>';
                
                try {
                    const res = await fetch('api.php?action=get_admin_logs', {
                        headers: { 'Authorization': 'Bearer ' + this.state.token }
                    });
                    const data = await res.json();
                    
                    if (data.logs) {
                        view.innerHTML = data.logs.map(l => `<div><span style="opacity:0.5">[${l.ts}]</span> ${l.msg}</div>`).join('');
                    } else {
                        view.innerHTML = '<span style="color:var(--danger)">Connection Refused.</span>';
                    }
                } catch (e) {
                    view.innerHTML = '<span style="color:var(--danger)">Network Error.</span>';
                }
            },

            async getAdminData() {
                const log = document.getElementById('admin-log');
                log.innerText = 'Requesting sensitive clearance...';
                
                try {
                    const res = await fetch('api.php?action=admin_debug', {
                        method: 'POST',
                        headers: { 'Authorization': 'Bearer ' + localStorage.getItem('nexus_token') }
                    });
                    const data = await res.json();
                    
                    if (data.sys_conf) {
                        log.innerHTML = `<span style="color:var(--success)">ACCESS GRANTED: Root Config Live</span><br>` +
                                        `ENV: ${data.sys_conf.environment}<br>` +
                                        `KEY: ${data.sys_conf.system_key}`;
                    } else {
                        log.innerText = "ACCESS DENIED: " + (data.error || "Insufficient/Invalid Credentials");
                    }
                } catch (e) {
                    log.innerText = "Connection Error";
                }
            },

            async refreshFinance() {
                const res = await fetch('api.php?action=get_balance', {
                    headers: { 'Authorization': 'Bearer ' + this.state.token }
                });
                const data = await res.json();
                document.getElementById('balance-checking').innerText = data.checking.toFixed(2);
                document.getElementById('balance-vault').innerText = data.vault.toFixed(2);
            },

            async transfer() {
                const amount = document.getElementById('transfer-amount').value;
                const log = document.getElementById('finance-log');
                const ts = new Date().toLocaleTimeString();
                log.innerText = `[${ts}] Initiating transfer request...`;
                
                const res = await fetch('api.php?action=transfer', {
                    method: 'POST',
                    body: JSON.stringify({ amount: parseFloat(amount) }),
                    headers: { 'Authorization': 'Bearer ' + this.state.token }
                });
                const data = await res.json();
                log.innerText += `\n[${new Date().toLocaleTimeString()}] ${data.message || data.error}`;
                this.refreshFinance();
            },
            
            async buyReport() {
                const log = document.getElementById('finance-log');
                const ts = new Date().toLocaleTimeString();
                log.innerText = `[${ts}] Purchasing Premium Report (200 Credits)...`;
                
                const res = await fetch('api.php?action=buy_flag', {
                    method: 'POST',
                    headers: { 'Authorization': 'Bearer ' + this.state.token }
                });
                const data = await res.json();
                
                if (data.status === 'delivered') {
                    log.innerText = data.report_content;
                } else {
                    log.innerText = data.error || "Transaction Failed";
                }
                this.refreshFinance();
            },

            async verifyConfig() {
                const log = document.getElementById('config-log');
                log.innerText = 'Verifying key configuration...';
                
                const key = document.getElementById('master-key').value;

                const res = await fetch('api.php?action=verify_config', {
                    method: 'POST',
                    body: JSON.stringify({ key: key }),
                    headers: { 'Authorization': 'Bearer ' + this.state.token }
                });
                const data = await res.json();
                
                if (data.success) {
                    log.innerText = "CONFIG VERIFIED. HASH: " + data.config_hash;
                } else {
                    log.innerText = "VERIFICATION FAILED: " + (data.error || "Invalid Key");
                }
            }
        };

        app.init();
    </script>
</body>
</html>
