// Initialize the packet counter
let packetCount = 0;

// Establish Socket.IO connection
const socket = io();

socket.on('new_malicious_ip', function(ipData) {
    const ipsList = document.getElementById('ips-list');
    
    // Create a new div for the new IP and append it to the list
    const ipDiv = document.createElement('div');
    ipDiv.classList.add('ip-entry');
    ipDiv.innerHTML = `
        <p><strong>IP:</strong> ${ipData.ip}</p>
        <p><strong>Score:</strong> ${ipData.score}</p>
        <p><strong>Is Malicious:</strong> ${ipData.is_malicious}</p>
        <p><strong>Last Reported:</strong> ${ipData.last_reported}</p>
        <p><strong>Reports:</strong> ${ipData.reports}</p>
        <p><strong>Domain:</strong> ${ipData.domain}</p>
        <p><strong>Usage Type:</strong> ${ipData.usage_type}</p>
        <p><strong>Hostnames:</strong> ${ipData.hostnames.join(", ")}</p>
        <p><strong>Country:</strong> ${ipData.country_name} (${ipData.country})</p>
        <p><strong>ISP:</strong> ${ipData.isp}</p>
    `;
    ipsList.prepend(ipDiv);
});


// Listen for incoming packet data from the server
socket.on("packet", function(data) {
    console.log("Received packet data: ", data);

    // Increment the packet count
    packetCount++;

    // Create a new packet card
    const packetCard = document.createElement("div");
    packetCard.classList.add("packet-card");

    // Add packet header with packet number
    const packetHeader = document.createElement("div");
    packetHeader.classList.add("packet-header");
    packetHeader.textContent = `Packet #${packetCount}`;

    // Add packet summary details
    const packetSummary = document.createElement("div");
    packetSummary.classList.add("packet-summary");
    packetSummary.textContent = data.summary;

    // Add timestamp
    const timestamp = document.createElement("div");
    timestamp.classList.add("timestamp");
    timestamp.textContent = new Date().toLocaleString();

    // Add footer with timestamp and packet number
    const packetFooter = document.createElement("div");
    packetFooter.classList.add("packet-footer");
    packetFooter.innerHTML = `<span class="packet-number">#${packetCount}</span> | ${timestamp.textContent}`;

    // Append elements to the packet card
    packetCard.appendChild(packetHeader);
    packetCard.appendChild(packetSummary);
    packetCard.appendChild(packetFooter);

    // Add the packet card to the container
    document.getElementById("packets").prepend(packetCard);
});