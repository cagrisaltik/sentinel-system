const agentSelect = document.getElementById("agentSelect");
const timeSelect = document.getElementById("timeSelect");

const chart = new ApexCharts(document.querySelector("#chart"), {
    series: [{ name: "Ort. Gecikme", data: [] }],
    chart: { type: "area", height: 350, background: "#1e293b", foreColor: "#cbd5e1", toolbar: { show: true } },
    stroke: { curve: "smooth", width: 2 },
    fill: { type: "gradient", gradient: { shadeIntensity: 1, opacityFrom: 0.7, opacityTo: 0.3 } },
    dataLabels: { enabled: false },
    xaxis: { type: "category" },
    colors: ["#3b82f6"]
});

const grid = new gridjs.Grid({
    columns: ["Ajan", "Hedef", "Ort. Ping (ms)", "Max Ping", "Başarılı", "Hatalı"],
    data: [],
    search: true,
    sort: true,
    pagination: { limit: 5 },
    style: {
        table: { width: "100%" },
        th: { "background-color": "#334155", color: "#fff" }
    }
}).render(document.getElementById("table"));

async function fetchJSON(url) {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    if (response.status === 401) {
        window.location.assign("/login.html");
        throw new Error("Authentication required");
    }
    if (!response.ok) {
        throw new Error("Request failed");
    }
    return response.json();
}

async function loadAgents() {
    const agents = await fetchJSON("/api/agents");
    agents.forEach((agent) => {
        const option = document.createElement("option");
        option.value = agent;
        option.textContent = agent;
        agentSelect.appendChild(option);
    });
}

async function updateChart() {
    const query = new URLSearchParams({ mode: timeSelect.value, agent: agentSelect.value });
    const data = await fetchJSON(`/api/chart?${query.toString()}`);
    await chart.updateSeries([{
        data: data.map((item) => ({ x: item.label, y: Math.round(item.value) }))
    }]);
}

async function updateTable() {
    const data = await fetchJSON("/api/table");
    grid.updateConfig({
        data: data.map((item) => [item.agent, item.target, Math.round(item.avg_ping), item.max_ping, item.success, item.fail])
    }).forceRender();
}

function refreshDashboard() {
    updateChart().catch(() => {});
    updateTable().catch(() => {});
}

agentSelect.addEventListener("change", refreshDashboard);
timeSelect.addEventListener("change", refreshDashboard);
document.getElementById("logoutButton").addEventListener("click", async () => {
    try {
        await fetch("/api/logout", { method: "POST" });
    } finally {
        window.location.assign("/login.html");
    }
});

chart.render();
loadAgents().then(refreshDashboard).catch(() => {});
window.setInterval(refreshDashboard, 30000);
