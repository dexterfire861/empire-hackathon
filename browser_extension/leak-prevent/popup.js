function setPopupState(result) {
  document.querySelector("#score").textContent = result.riskScore ?? "--";
  document.querySelector("#riskLabel").textContent = result.riskLabel || "Unknown";
  document.querySelector("#domainLabel").textContent = `${result.domain || "Unknown domain"} · ${result.siteType || "general"}`;
  document.querySelector("#legalNote").textContent = result.legalNote || "";

  const signalList = document.querySelector("#signalList");
  signalList.innerHTML = "";
  (result.signals || []).forEach((signal) => {
    const li = document.createElement("li");
    li.textContent = signal;
    signalList.appendChild(li);
  });
}

async function fetchCurrentAnalysis() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  const response = await chrome.runtime.sendMessage({
    type: "GET_PAGE_ANALYSIS",
    tabId: tab.id,
    url: tab.url,
  });

  if (response) {
    setPopupState(response);
  }
}

document.querySelector("#saveLead").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  const response = await chrome.runtime.sendMessage({
    type: "SAVE_RESCUE_LEAD",
    tabId: tab.id,
    url: tab.url,
  });

  document.querySelector("#saveLead").textContent = response?.ok ? "Opened Rescue" : "Retry Rescue";
});

fetchCurrentAnalysis().catch(() => {
  setPopupState({
    riskScore: 0,
    riskLabel: "Unavailable",
    domain: "Unable to inspect current tab",
    siteType: "general",
    signals: ["Open a web page to inspect collection and tracking signals."],
    legalNote: "Start the Specter backend and set the dashboard URL in extension settings.",
  });
});
