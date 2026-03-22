const DEFAULT_SETTINGS = {
  homeState: "CA",
  sensitivity: "balanced",
  dashboardUrl: "http://127.0.0.1:8000",
  installSource: "Leakipedia-dashboard",
  deviceId: "browser-local",
};

const EMPTY_ANALYSIS = {
  riskScore: 0,
  riskLabel: "Idle",
  domain: "No active page",
  siteType: "general",
  signals: ["Open a page and focus a form field to run Leak Prevent."],
  steps: ["Use the popup to review the latest analysis."],
  trackersDetected: [],
  dataTypesShared: [],
};

async function getSettings() {
  return chrome.storage.sync.get(DEFAULT_SETTINGS);
}

function currentIso() {
  return new Date().toISOString();
}

function hoursBetween(a, b) {
  return Math.abs(new Date(a).getTime() - new Date(b).getTime()) / (1000 * 60 * 60);
}

async function persistAnalysis(tabId, analysis) {
  const { pageAnalyses = {} } = await chrome.storage.local.get(["pageAnalyses"]);
  pageAnalyses[String(tabId)] = { ...analysis, updatedAt: currentIso() };
  await chrome.storage.local.set({
    latestAnalysis: analysis,
    pageAnalyses,
  });
}

async function upsertSiteLog(analysis) {
  if (!analysis?.shouldLog || !analysis?.storageRecord?.site) return;

  const { siteLogs = [] } = await chrome.storage.local.get(["siteLogs"]);
  const next = [...siteLogs];
  const existingIndex = next.findIndex(
    (entry) => entry.site === analysis.storageRecord.site && hoursBetween(entry.timestamp, analysis.storageRecord.timestamp) < 6
  );

  if (existingIndex >= 0) {
    next[existingIndex] = {
      ...next[existingIndex],
      ...analysis.storageRecord,
      data_types_shared: Array.from(new Set([...(next[existingIndex].data_types_shared || []), ...(analysis.storageRecord.data_types_shared || [])])),
      trackers_detected: Array.from(new Set([...(next[existingIndex].trackers_detected || []), ...(analysis.storageRecord.trackers_detected || [])])),
    };
  } else {
    next.unshift(analysis.storageRecord);
  }

  await chrome.storage.local.set({ siteLogs: next.slice(0, 250) });
}

function summarizeWeek(siteLogs) {
  const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const weekly = siteLogs.filter((entry) => new Date(entry.timestamp).getTime() >= weekAgo);
  return {
    sitesSharedCount: new Set(weekly.map((entry) => entry.site)).size,
    entries: weekly.length,
    brokersVisited: weekly.filter((entry) => entry.legal_note?.toLowerCase().includes("broker")).length,
  };
}

async function analyzeWithBackend(payload) {
  const settings = await getSettings();
  const response = await fetch(`${settings.dashboardUrl.replace(/\/$/, "")}/extension/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...payload,
      user_state: settings.homeState,
      install_source: settings.installSource,
      device_id: settings.deviceId,
    }),
  });

  if (!response.ok) {
    throw new Error(`Analysis failed (${response.status})`);
  }

  return response.json();
}

async function saveRescueLeadRemotely(lead) {
  const settings = await getSettings();
  const response = await fetch(`${settings.dashboardUrl.replace(/\/$/, "")}/extension/rescue-lead`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      saved_at: lead.savedAt,
      page: lead.page,
      analysis: lead.analysis,
      source: "leak-prevent-extension",
    }),
  });

  if (!response.ok) {
    throw new Error(`Rescue handoff failed (${response.status})`);
  }

  return response.json();
}

async function openSidePanelForSender(sender) {
  if (!sender.tab?.windowId) return { ok: false };
  await chrome.sidePanel.open({ windowId: sender.tab.windowId });
  return { ok: true };
}

chrome.runtime.onInstalled.addListener(async () => {
  const settings = await chrome.storage.sync.get(DEFAULT_SETTINGS);
  await chrome.storage.sync.set({ ...DEFAULT_SETTINGS, ...settings });
  await chrome.storage.local.set({ latestAnalysis: EMPTY_ANALYSIS });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_PAGE") {
    analyzeWithBackend(message.payload)
      .then(async (analysis) => {
        if (sender.tab?.id !== undefined) {
          await persistAnalysis(sender.tab.id, analysis);
        } else {
          await chrome.storage.local.set({ latestAnalysis: analysis });
        }
        await upsertSiteLog(analysis);
        sendResponse(analysis);
      })
      .catch(async (error) => {
        const fallback = {
          ...EMPTY_ANALYSIS,
          domain: message.payload?.url ? new URL(message.payload.url).hostname : "Unknown domain",
          riskLabel: "Unavailable",
          signals: [`Leak Prevent could not reach the Leakipedia backend: ${error.message}`],
        };
        await chrome.storage.local.set({ latestAnalysis: fallback });
        sendResponse(fallback);
      });
    return true;
  }

  if (message.type === "GET_PAGE_ANALYSIS") {
    chrome.storage.local.get(["pageAnalyses", "latestAnalysis"]).then(({ pageAnalyses = {}, latestAnalysis }) => {
      const tabAnalysis = message.tabId !== undefined ? pageAnalyses[String(message.tabId)] : null;
      sendResponse(tabAnalysis || latestAnalysis || EMPTY_ANALYSIS);
    });
    return true;
  }

  if (message.type === "GET_WEEKLY_SUMMARY") {
    chrome.storage.local.get(["siteLogs"]).then(({ siteLogs = [] }) => {
      sendResponse(summarizeWeek(siteLogs));
    });
    return true;
  }

  if (message.type === "SAVE_RESCUE_LEAD") {
    chrome.storage.local.get(["latestAnalysis"]).then(({ latestAnalysis }) => {
      const lead = {
        savedAt: currentIso(),
        page: message.url,
        analysis: latestAnalysis || EMPTY_ANALYSIS,
      };
      chrome.storage.local.set({ rescueLead: lead }).then(async () => {
        try {
          const remote = await saveRescueLeadRemotely(lead);
          const settings = await getSettings();
          const rescueUrl = `${settings.dashboardUrl.replace(/\/$/, "")}${remote.rescue_url}`;
          await chrome.tabs.create({ url: rescueUrl });
          sendResponse({ ok: true, rescueUrl });
        } catch (error) {
          sendResponse({ ok: false, error: error.message });
        }
      });
    });
    return true;
  }

  if (message.type === "OPEN_SIDE_PANEL_FROM_PAGE") {
    openSidePanelForSender(sender)
      .then((result) => sendResponse(result))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  return false;
});
