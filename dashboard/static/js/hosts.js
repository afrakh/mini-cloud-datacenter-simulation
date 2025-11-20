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

        // Servers
        servers.forEach(s => {
            const card = document.createElement('div');
            card.className = 'card p-2 m-1';
            card.style.width = '150px';
            card.style.backgroundColor = s.status === 'UP' ? '#d4edda' : '#f8d7da';
            card.innerHTML = `<strong>${s.id}</strong><br>${s.ip}<br>Status: ${s.status}`;
            serversDiv.appendChild(card);
        });

        // Hosts
        hosts.forEach(h => {
            const card = document.createElement('div');
            card.className = 'card p-2 m-1';
            card.style.width = '150px';
            card.style.backgroundColor = h.status === 'UP' ? '#d1ecf1' : '#f8d7da';
            let typeLabel = h.type ? ` (${h.type})` : '';
            card.innerHTML = `<strong>${h.id}</strong>${typeLabel}<br>${h.ip}<br>Status: ${h.status}`;
            clientsDiv.appendChild(card);  // only once
        });

    } catch (err) {
        console.error("Error loading servers/hosts:", err);

        // Show error message instead of empty boxes
        const serversDiv = document.getElementById('servers');
        const clientsDiv = document.getElementById('clients');
        if (serversDiv) serversDiv.innerText = "Error loading servers";
        if (clientsDiv) clientsDiv.innerText = "Error loading clients";
    }
}

// Load on page load + refresh every 5s
window.addEventListener('load', () => {
    loadHosts();
    setInterval(loadHosts, 5000);
});
