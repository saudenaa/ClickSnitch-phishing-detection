// --- Update Gauge Color + Text ---
function updateGauge(resultText, colorClass, displayText) {
  const gaugeCircle = document.getElementById("gaugeCircle");
  const gaugeText = document.getElementById("gaugeText");
  const label = document.getElementById("statusLabel");

  label.textContent = "Status: " + resultText;
  gaugeText.textContent = displayText;

  gaugeCircle.className = "gauge-circle " + colorClass;
}

// --- Scan URL Without Login ---
async function scanURL() {
  const url = document.getElementById("urlInput").value.trim();

  if (!url) {
    updateGauge("Enter a URL", "", "--");
    return;
  }

  updateGauge("Scanning...", "", "...");

  try {
    const response = await fetch("http://127.0.0.1:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    const data = await response.json();

    if (data.result === "phishing") {
      updateGauge("PHISHING ⚠️", "gauge-danger", "⚠");
    } else if (data.result === "legitimate") {
      updateGauge("SAFE ✓", "gauge-safe", "✓");
    } else {
      updateGauge("Unknown", "", "?");
    }

    // Save history locally
    let recent = JSON.parse(localStorage.getItem("recentScans") || "[]");
    recent.unshift({ url, result: data.result, time: new Date().toLocaleString() });
    if (recent.length > 5) recent = recent.slice(0, 5);
    localStorage.setItem("recentScans", JSON.stringify(recent));

    showRecentScans();

  } catch (err) {
    updateGauge("Backend Error", "", "X");
  }
}

// Display Local History
function showRecentScans() {
  const list = document.getElementById("recentScans");
  const list2 = document.getElementById("recentScansDashboard");

  let recent = JSON.parse(localStorage.getItem("recentScans") || "[]");

  if (list)
    list.innerHTML = recent.map(item =>
      `<li>${item.url} 
      <span style="color:${item.result === "phishing" ? "var(--danger)" : "var(--safe)"}">[${item.result}]</span>
      <br><small>${item.time}</small></li>`
    ).join("");

  if (list2)
    list2.innerHTML = list.innerHTML;
}

showRecentScans();
