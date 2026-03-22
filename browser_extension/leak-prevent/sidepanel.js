function renderPanel(data) {
  document.querySelector("#panelDomain").textContent = data.domain;
  document.querySelector("#panelSummary").textContent = `${data.riskLabel} risk score ${data.riskScore}/100. ${data.legalNote || ""}`.trim();

  const panelSignals = document.querySelector("#panelSignals");
  const panelSteps = document.querySelector("#panelSteps");
  const panelTrackers = document.querySelector("#panelTrackers");
  panelSignals.innerHTML = "";
  panelSteps.innerHTML = "";
  panelTrackers.innerHTML = "";

  (data.signals || []).forEach((signal) => {
    const li = document.createElement("li");
    li.textContent = signal;
    panelSignals.appendChild(li);
  });

  (data.steps || []).forEach((step) => {
    const li = document.createElement("li");
    li.textContent = step;
    panelSteps.appendChild(li);
  });

  (data.trackersDetected || ["No major trackers detected"]).forEach((tracker) => {
    const li = document.createElement("li");
    li.textContent = tracker;
    panelTrackers.appendChild(li);
  });
}

async function loadPanel() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  const response = await chrome.runtime.sendMessage({
    type: "GET_PAGE_ANALYSIS",
    tabId: tab.id,
    url: tab.url,
  });

  if (response) {
    renderPanel(response);
  }
}

loadPanel().catch(() => {
  renderPanel({
    domain: "No supported page",
    riskLabel: "Unknown",
    riskScore: 0,
    signals: ["Open a web page to inspect collection and tracking signals."],
    steps: ["Use the popup to refresh once a page is active."],
    trackersDetected: ["No tracker data available"],
  });
});
