document.addEventListener("DOMContentLoaded", function() {

    function loadLogs() {
        const logsContainer = document.getElementById("logsContainer");
        if (!logsContainer) {
            console.error("logsContainer div not found!");
            return;
        }

        fetch("/api/logs")
            .then(resp => resp.json())
            .then(data => {
                logsContainer.innerHTML = ""; // clear previous
                if (!data || data.length === 0) {
                    logsContainer.innerHTML = "<p>No logs available</p>";
                    return;
                }

                // Show logs
                data.forEach(file => {
                    const div = document.createElement("div");
                    div.className = "log-file p-2 mb-2 rounded shadow-sm";
                    div.innerHTML = `<strong>${file.name}</strong> - ${file.timestamp}<pre>${file.content}</pre>`;
                    logsContainer.appendChild(div);
                });
            })
            .catch(err => console.error("Error loading logs:", err));
    }

    loadLogs();                 // initial load
    setInterval(loadLogs, 5000); // refresh every 5 seconds
});

