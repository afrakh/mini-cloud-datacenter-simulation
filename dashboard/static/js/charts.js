// charts.js

let requestsChart = null;
let bandwidthChart = null;

// Initialize charts only once
function initCharts() {
    const ctxReq = document.getElementById('requestsChart').getContext('2d');
    const ctxBW = document.getElementById('bandwidthChart').getContext('2d');

    requestsChart = new Chart(ctxReq, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Requests',
                data: [],
                borderColor: 'blue',
                fill: false,
                tension: 0.2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { x: { display: true }, y: { display: true } }
        }
    });

    bandwidthChart = new Chart(ctxBW, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Bandwidth',
                data: [],
                borderColor: 'green',
                fill: false,
                tension: 0.2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { x: { display: true }, y: { display: true } }
        }
    });
}

// Fetch stats from API and update charts
async function updateCharts() {
    try {
        const res = await fetch('/api/get-stats');
        if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
        const stats = await res.json();

        const labels = stats.map(s => new Date(s.ts).toLocaleTimeString());
        const requests = stats.map(s => s.requests || 0);
        const bandwidth = stats.map(s => s.bandwidth || 0);

        requestsChart.data.labels = labels;
        requestsChart.data.datasets[0].data = requests;
        requestsChart.update();

        bandwidthChart.data.labels = labels;
        bandwidthChart.data.datasets[0].data = bandwidth;
        bandwidthChart.update();
    } catch (err) {
        console.error("Error loading stats:", err);
    }
}

// Initialize and refresh every 5s
window.addEventListener('load', () => {
    initCharts();
    updateCharts();
    setInterval(updateCharts, 5000);
});
