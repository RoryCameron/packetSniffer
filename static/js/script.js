// Initialize the packet counter
let packetCount = 0;

// Establish Socket.IO connection
const socket = io();

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