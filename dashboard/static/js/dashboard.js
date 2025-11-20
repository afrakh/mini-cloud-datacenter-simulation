// dashboard.js

let requestsChart, bandwidthChart;

// ---------------- Load Hosts & Servers ----------------
async function loadHosts() {
    try {
        const [serversRes, hostsRes] = await Promise.all([
            fetch('/api/active-servers'),
            fetch('/api/active-hosts')
        ]);
        const servers = await serversRes.json();
        const hosts = await hostsRes.json();

        const serversDiv = document.getElementById('servers');
        const clientsDiv = document.getElementById('clients');
        serversDiv.innerHTML = '';
        clientsDiv.innerHTML = '';

        servers.forEach(s => {
            const card = document.createElement('div');
            card.className = 'card p-2 m-1';
            card.style.width = '150px';
            card.style.backgroundColor = s.status === 'UP' ? '#d4edda' : '#f8d7da';
            card.innerHTML = `<strong>${s.id}</strong><br>${s.ip}<br>Status: ${s.status}`;
            serversDiv.appendChild(card);
        });

        hosts.forEach(h => {
            const card = document.createElement('div');
            card.className = 'card p-2 m-1';
            card.style.width = '150px';
            card.style.backgroundColor = h.status === 'UP' ? '#d1ecf1' : '#f8d7da';
            card.innerHTML = `<strong>${h.id}</strong><br>${h.ip}<br>Status: ${h.status}`;
            clientsDiv.appendChild(card);
        });

    } catch (err) {
        console.error("Error loading hosts/servers:", err);
    }
}

// ---------------- Load Stats for Charts ----------------
// ---------------- Load Stats for Charts ----------------
async function loadStats() {
    try {
        const res = await fetch('/api/get-stats');
        const stats = await res.json();
        if (!stats || stats.length === 0) return;

        // ---- GROUP & SUM BY TIMESTAMP ----
        let summed = {};  
        stats.forEach(s => {
            if (!summed[s.ts]) {
                summed[s.ts] = { requests: 0, bandwidth: 0 };
            }
            summed[s.ts].requests += s.requests;
            summed[s.ts].bandwidth += s.bandwidth;
        });

        const tsLabels = Object.keys(summed).map(ts =>
            new Date(ts * 1000).toLocaleTimeString()
        );

        const requestsData = Object.values(summed).map(v => v.requests);
        const bandwidthData = Object.values(summed).map(v => v.bandwidth);

        // ----- REQUESTS CHART -----
        if (!requestsChart) {
            const ctx1 = document.getElementById('requestsChart').getContext('2d');
            requestsChart = new Chart(ctx1, {
                type: 'line',
                data: {
                    labels: tsLabels,
                    datasets: [{
                        label: 'Requests',
                        data: requestsData,
                        borderColor: 'blue',
                        fill: false
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });
        } else {
            requestsChart.data.labels = tsLabels;
            requestsChart.data.datasets[0].data = requestsData;
            requestsChart.update();
        }

        // ----- BANDWIDTH CHART -----
        if (!bandwidthChart) {
            const ctx2 = document.getElementById('bandwidthChart').getContext('2d');
            bandwidthChart = new Chart(ctx2, {
                type: 'line',
                data: {
                    labels: tsLabels,
                    datasets: [{
                        label: 'Bandwidth',
                        data: bandwidthData,
                        borderColor: 'green',
                        fill: false
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false }
            });
        } else {
            bandwidthChart.data.labels = tsLabels;
            bandwidthChart.data.datasets[0].data = bandwidthData;
            bandwidthChart.update();
        }

    } catch (err) {
        console.error("Error loading stats:", err);
    }
}

// ---------------- Auto Refresh ----------------
window.addEventListener('load', () => {
    loadHosts();
    loadStats();
    setInterval(loadHosts, 3000);
    setInterval(loadStats, 3000);
});
