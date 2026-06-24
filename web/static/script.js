document.addEventListener('DOMContentLoaded', () => {
    // Colors from CSS
    const primaryCyan = '#00f2ff';
    const secondaryPurple = '#bd00ff';
    const dangerRed = '#ff003c';
    const warningAmber = '#ffa500';
    const glassBorder = 'rgba(255, 255, 255, 0.1)';

    // Global Chart instances
    let threatsChart = null;
    let logVolumeChart = null;

    // Initialize the app
    init();

    function init() {
        // Setup Charts with empty data
        initCharts();
        
        // Initial Fetch
        fetchSysinfo();
        fetchStats();
        fetchLogs();

        // Set intervals for live updates
        setInterval(fetchSysinfo, 5000); // 5 seconds
        setInterval(fetchStats, 10000);  // 10 seconds
        setInterval(fetchLogs, 10000);   // 10 seconds
    }

    async function fetchSysinfo() {
        try {
            const res = await fetch('/api/sysinfo');
            if (!res.ok) return;
            const data = await res.json();
            
            document.getElementById('sys-cpu').textContent = data.cpu.toFixed(1) + '%';
            document.getElementById('sys-ram').textContent = data.ram.toFixed(1) + '%';
            document.getElementById('sys-uptime').textContent = data.uptime;
        } catch (e) {
            console.error('Failed to fetch sysinfo', e);
        }
    }

    async function fetchStats() {
        try {
            const res = await fetch('/api/stats');
            if (!res.ok) return;
            const data = await res.json();
            
            // Update Metric Cards
            document.getElementById('metric-total').textContent = data.total_threats || 0;
            document.getElementById('metric-unresolved').textContent = data.unresolved || 0;
            document.getElementById('metric-processes').textContent = data.active_processes || 0;
            document.getElementById('metric-scanned').textContent = data.scanned_files || 0;
            document.getElementById('metric-network').textContent = data.network_connections || 0;

            // Update Charts
            updateCharts(data);
        } catch (e) {
            console.error('Failed to fetch stats', e);
        }
    }

    async function fetchLogs() {
        try {
            const res = await fetch('/api/logs?limit=10');
            if (!res.ok) return;
            const data = await res.json();
            
            const tbody = document.getElementById('logs-table-body');
            tbody.innerHTML = '';
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center">No logs found.</td></tr>';
                return;
            }

            data.forEach(log => {
                const tr = document.createElement('tr');
                
                // Formating time
                const date = new Date(log.timestamp);
                const timeStr = isNaN(date.getTime()) ? log.timestamp : date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
                
                // Badge class
                let badgeClass = 'badge-info';
                if (log.level === 'WARN') badgeClass = 'badge-warn';
                if (log.level === 'ERROR' || log.level === 'HIGH') badgeClass = 'badge-error';

                tr.innerHTML = `
                    <td>${timeStr}</td>
                    <td><span class="badge ${badgeClass}">${log.level}</span></td>
                    <td>${log.source || 'system'}</td>
                    <td>${log.message}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Failed to fetch logs', e);
        }
    }

    function initCharts() {
        Chart.defaults.color = '#b9cacb';
        Chart.defaults.font.family = "'JetBrains Mono', monospace";
        
        // Threats by Type (Doughnut)
        const ctxThreats = document.getElementById('threatsTypeChart').getContext('2d');
        threatsChart = new Chart(ctxThreats, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [primaryCyan, secondaryPurple, dangerRed, warningAmber],
                    borderColor: '#111318',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { boxWidth: 12, font: {size: 11} }
                    }
                },
                cutout: '75%'
            }
        });

        // Log Volume (Area)
        const ctxVolume = document.getElementById('logVolumeChart').getContext('2d');
        logVolumeChart = new Chart(ctxVolume, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Logs',
                    data: [],
                    borderColor: primaryCyan,
                    backgroundColor: 'rgba(0, 242, 255, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: primaryCyan,
                    pointRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { 
                        beginAtZero: true, 
                        grid: { color: glassBorder } 
                    },
                    x: { 
                        grid: { color: glassBorder } 
                    }
                }
            }
        });
    }

    function updateCharts(data) {
        // Update Doughnut Chart
        if (data.threats_by_type && Object.keys(data.threats_by_type).length > 0) {
            const labels = Object.keys(data.threats_by_type);
            const values = Object.values(data.threats_by_type);
            threatsChart.data.labels = labels;
            threatsChart.data.datasets[0].data = values;
        } else {
            threatsChart.data.labels = ['No Data'];
            threatsChart.data.datasets[0].data = [1];
            threatsChart.data.datasets[0].backgroundColor = ['#333539'];
        }
        threatsChart.update();

        // Update Line Chart
        if (data.log_volume && data.log_volume.length > 0) {
            logVolumeChart.data.labels = data.log_volume.map(v => v.date);
            logVolumeChart.data.datasets[0].data = data.log_volume.map(v => v.count);
        } else {
            // Mock data if empty for demo purposes or show empty
            const days = Array.from({length: 7}, (_, i) => {
                const d = new Date(); d.setDate(d.getDate() - (6 - i)); 
                return d.toISOString().split('T')[0];
            });
            logVolumeChart.data.labels = days;
            logVolumeChart.data.datasets[0].data = [0,0,0,0,0,0,0];
        }
        logVolumeChart.update();
    }

    // Tab switching
    const navItems = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetTab = item.getAttribute('data-tab');
            
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');
            
            tabPanes.forEach(pane => pane.style.display = 'none');
            const targetPane = document.getElementById('tab-' + targetTab);
            if(targetPane) targetPane.style.display = 'block';
            
            // Trigger fetch based on tab
            if (targetTab === 'detection-logs') fetchFullLogs();
            if (targetTab === 'network-logs') fetchNetworkLogs();
            if (targetTab === 'threat-history') fetchThreatHistory();
            if (targetTab === 'settings') fetchSettings();
        });
    });

    // Save settings button
    const btnSaveSettings = document.getElementById('btn-save-settings');
    if (btnSaveSettings) {
        btnSaveSettings.addEventListener('click', saveSettings);
    }

    async function fetchSettings() {
        try {
            const res = await fetch('/api/settings');
            if (!res.ok) return;
            const data = await res.json();
            
            document.getElementById('vt-api-key').value = data.vt_api_key || '';
            document.getElementById('email-sender').value = data.email_sender || '';
            document.getElementById('email-password').value = data.email_password || '';
            document.getElementById('email-receiver').value = data.email_receiver || '';
            document.getElementById('output-mode').value = data.output_mode || 'both';
            document.getElementById('syslog-host').value = data.syslog_host || '';
            document.getElementById('syslog-port').value = data.syslog_port || '';
            document.getElementById('abuseipdb-key').value = data.abuseipdb_key || '';
            document.getElementById('malwarebazaar-key').value = data.malwarebazaar_key || '';
        } catch (e) {
            console.error('Failed to fetch settings', e);
        }
    }

    async function saveSettings() {
        const payload = {
            vt_api_key: document.getElementById('vt-api-key').value,
            email_sender: document.getElementById('email-sender').value,
            email_password: document.getElementById('email-password').value,
            email_receiver: document.getElementById('email-receiver').value,
            output_mode: document.getElementById('output-mode').value,
            syslog_host: document.getElementById('syslog-host').value,
            syslog_port: parseInt(document.getElementById('syslog-port').value) || 514,
            abuseipdb_key: document.getElementById('abuseipdb-key').value,
            malwarebazaar_key: document.getElementById('malwarebazaar-key').value
        };

        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            if (res.ok) {
                const statusSpan = document.getElementById('settings-status');
                statusSpan.style.opacity = '1';
                setTimeout(() => statusSpan.style.opacity = '0', 3000);
            }
        } catch (e) {
            console.error('Failed to save settings', e);
        }
    }

    async function fetchFullLogs() {
        try {
            const res = await fetch('/api/logs?limit=500');
            if (!res.ok) return;
            const data = await res.json();
            
            const tbody = document.getElementById('full-logs-table-body');
            tbody.innerHTML = '';
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center">No logs found.</td></tr>';
                return;
            }

            data.forEach(log => {
                const tr = document.createElement('tr');
                const date = new Date(log.timestamp);
                const timeStr = isNaN(date.getTime()) ? log.timestamp : date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
                
                let badgeClass = 'badge-info';
                if (log.level === 'WARN') badgeClass = 'badge-warn';
                if (log.level === 'ERROR' || log.level === 'HIGH') badgeClass = 'badge-error';

                tr.innerHTML = `
                    <td>${timeStr}</td>
                    <td><span class="badge ${badgeClass}">${log.level}</span></td>
                    <td>${log.source || 'system'}</td>
                    <td>${log.message}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Failed to fetch full logs', e);
        }
    }

    async function fetchNetworkLogs() {
        try {
            const res = await fetch('/api/network?limit=500');
            if (!res.ok) return;
            const data = await res.json();
            
            const tbody = document.getElementById('network-table-body');
            tbody.innerHTML = '';
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center">No network logs found.</td></tr>';
                return;
            }

            data.forEach(log => {
                const tr = document.createElement('tr');
                const date = new Date(log.timestamp);
                const timeStr = isNaN(date.getTime()) ? log.timestamp : date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
                
                let badgeClass = 'badge-info';
                if (log.level === 'WARN') badgeClass = 'badge-warn';
                if (log.level === 'ERROR' || log.level === 'HIGH') badgeClass = 'badge-error';

                tr.innerHTML = `
                    <td>${timeStr}</td>
                    <td><span class="badge ${badgeClass}">${log.level || 'INFO'}</span></td>
                    <td>${log.source_ip || 'unknown'}</td>
                    <td>${log.message || 'connection recorded'}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Failed to fetch network logs', e);
        }
    }

    async function fetchThreatHistory() {
        try {
            const res = await fetch('/api/threats?limit=500');
            if (!res.ok) return;
            const data = await res.json();
            
            const tbody = document.getElementById('threats-table-body');
            tbody.innerHTML = '';
            
            if (data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center">No threats found.</td></tr>';
                return;
            }

            data.forEach(log => {
                const tr = document.createElement('tr');
                const date = new Date(log.timestamp);
                const timeStr = isNaN(date.getTime()) ? log.timestamp : date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
                
                let badgeClass = 'badge-warn';
                if (log.severity === 'HIGH') badgeClass = 'badge-error';
                if (log.severity === 'LOW') badgeClass = 'badge-info';
                
                const statusHtml = log.resolved 
                    ? '<span class="badge" style="background: rgba(0,255,0,0.1); color: #0f0; border: 1px solid #0f0;">RESOLVED</span>'
                    : '<span class="badge" style="background: rgba(255,0,0,0.1); color: #f00; border: 1px solid #f00;">OPEN</span>';

                tr.innerHTML = `
                    <td>${timeStr}</td>
                    <td><span class="badge ${badgeClass}">${log.severity || 'MEDIUM'}</span></td>
                    <td>${log.threat_type || 'unknown'}</td>
                    <td>${log.description || log.message || ''}</td>
                    <td>${statusHtml}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (e) {
            console.error('Failed to fetch threat history', e);
        }
    }
});
