const defaultSettings = {
  homeState: "CA",
  sensitivity: "balanced",
  dashboardUrl: "http://127.0.0.1:8000",
  userEmail: "",
};

async function loadSettings() {
  const stored = await chrome.storage.sync.get(defaultSettings);
  document.querySelector("#homeState").value = stored.homeState;
  document.querySelector("#sensitivity").value = stored.sensitivity;
  document.querySelector("#dashboardUrl").value = stored.dashboardUrl;
  document.querySelector("#userEmail").value = stored.userEmail;
}

document.querySelector("#settingsForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  await chrome.storage.sync.set({
    homeState: document.querySelector("#homeState").value,
    sensitivity: document.querySelector("#sensitivity").value,
    dashboardUrl: document.querySelector("#dashboardUrl").value.trim(),
    userEmail: document.querySelector("#userEmail").value.trim(),
  });
});

loadSettings();
