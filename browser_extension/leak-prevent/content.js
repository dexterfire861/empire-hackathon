const TRACKER_SIGNATURES = {
  meta_pixel: ["connect.facebook.net", "fbq("],
  google_analytics: ["googletagmanager.com", "google-analytics.com", "gtag("],
  tiktok_pixel: ["analytics.tiktok.com", "ttq.load"],
  klaviyo: ["static.klaviyo.com", "_learnq"],
  hotjar: ["static.hotjar.com", "hj("],
  segment: ["cdn.segment.com", "analytics.load"],
};

let warningNode = null;
let warningTimeout = null;
let lastFocusedFingerprint = "";
const MASKABLE_EMAIL_PROVIDERS = new Set([
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "fastmail.com",
  "proton.me",
  "protonmail.com",
]);

function cleanText(value) {
  return (value || "").toString().trim();
}

function findLabel(element) {
  if (!element) return "";
  if (element.labels?.length) {
    return cleanText(element.labels[0].textContent);
  }

  const parentLabel = element.closest("label");
  if (parentLabel) {
    return cleanText(parentLabel.textContent);
  }

  const labelledBy = element.getAttribute("aria-labelledby");
  if (labelledBy) {
    return labelledBy
      .split(/\s+/)
      .map((id) => document.getElementById(id))
      .filter(Boolean)
      .map((node) => cleanText(node.textContent))
      .join(" ");
  }

  return cleanText(element.getAttribute("aria-label"));
}

function serializeField(element) {
  return {
    name: cleanText(element.name),
    id: cleanText(element.id),
    type: cleanText(element.type || element.tagName.toLowerCase()),
    placeholder: cleanText(element.placeholder),
    label: findLabel(element),
    autocomplete: cleanText(element.autocomplete),
  };
}

function detectFormFields() {
  return Array.from(document.querySelectorAll("input, textarea, select"))
    .filter((element) => {
      const type = (element.type || "").toLowerCase();
      return !["hidden", "submit", "button", "reset"].includes(type);
    })
    .map(serializeField);
}

function detectTrackers() {
  const sources = [];
  const detected = new Set();

  Array.from(document.scripts).forEach((script) => {
    if (script.src) {
      sources.push(script.src);
    }
    if (script.textContent) {
      sources.push(script.textContent.slice(0, 2000));
    }
  });

  sources.forEach((source) => {
    const lower = source.toLowerCase();
    Object.entries(TRACKER_SIGNATURES).forEach(([tracker, signatures]) => {
      if (signatures.some((signature) => lower.includes(signature.toLowerCase()))) {
        detected.add(tracker);
      }
    });
  });

  return {
    trackersDetected: Array.from(detected),
    scriptSources: Array.from(
      new Set(
        Array.from(document.scripts)
          .map((script) => script.src)
          .filter(Boolean)
      )
    ),
  };
}

function detectPrivacyPolicy() {
  const policyLink = Array.from(document.querySelectorAll("a[href]")).find((anchor) =>
    /privacy|do not sell|your privacy choices/i.test(`${anchor.textContent} ${anchor.href}`)
  );
  return {
    privacyPolicyExists: Boolean(policyLink),
    privacyPolicyUrl: policyLink?.href || null,
  };
}

function detectDarkPatterns() {
  const patterns = [];
  if (document.querySelector('input[type="checkbox"][checked]')) {
    patterns.push("prechecked_checkbox");
  }
  const cookieText = document.body?.innerText?.slice(0, 5000) || "";
  if (/accept all/i.test(cookieText) && !/reject all/i.test(cookieText)) {
    patterns.push("accept_all_without_reject");
  }
  if (/\b\d{1,2}:\d{2}\b/.test(cookieText) || /offer expires|limited time/i.test(cookieText)) {
    patterns.push("countdown_timer");
  }
  return Array.from(new Set(patterns));
}

function buildSnapshot(focusedField = null) {
  const trackers = detectTrackers();
  const policy = detectPrivacyPolicy();

  return {
    url: location.href,
    title: document.title,
    page_text_excerpt: document.body?.innerText?.slice(0, 4000) || "",
    form_fields: detectFormFields(),
    focused_field: focusedField,
    trackers_detected: trackers.trackersDetected,
    script_sources: trackers.scriptSources,
    privacy_policy_exists: policy.privacyPolicyExists,
    privacy_policy_url: policy.privacyPolicyUrl,
    dark_patterns_detected: detectDarkPatterns(),
    gpc_enabled: Boolean(navigator.globalPrivacyControl),
  };
}

function isEmailField(field) {
  const blob = [
    field?.type,
    field?.name,
    field?.id,
    field?.placeholder,
    field?.label,
    field?.autocomplete,
  ]
    .map((value) => cleanText(value).toLowerCase())
    .join(" ");

  return /\bemail\b/.test(blob) || field?.type === "email";
}

function sanitizeSiteTag(hostname) {
  return cleanText(hostname)
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 18);
}

function buildMaskedEmail(userEmail, hostname) {
  const trimmed = cleanText(userEmail).toLowerCase();
  const match = trimmed.match(/^([^@]+)@([^@]+)$/);
  if (!match) return null;

  const [, localPart, domain] = match;
  if (!MASKABLE_EMAIL_PROVIDERS.has(domain)) {
    return {
      value: null,
      supported: false,
      reason: "Email aliases are only auto-generated for common plus-address providers.",
    };
  }

  const siteTag = sanitizeSiteTag(hostname || location.hostname || "site") || "site";
  return {
    value: `${localPart}+${siteTag}@${domain}`,
    supported: true,
  };
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const temp = document.createElement("textarea");
    temp.value = text;
    temp.style.position = "fixed";
    temp.style.opacity = "0";
    document.body.appendChild(temp);
    temp.focus();
    temp.select();
    const copied = document.execCommand("copy");
    temp.remove();
    return copied;
  }
}

function hideWarning() {
  if (warningTimeout) {
    clearTimeout(warningTimeout);
    warningTimeout = null;
  }
  if (warningNode) {
    warningNode.remove();
    warningNode = null;
  }
}

async function showWarning(analysis) {
  hideWarning();

  warningNode = document.createElement("div");
  warningNode.setAttribute("data-privasee-warning", "true");
  warningNode.style.position = "fixed";
  warningNode.style.top = "18px";
  warningNode.style.right = "18px";
  warningNode.style.zIndex = "2147483647";
  warningNode.style.maxWidth = "320px";
  warningNode.style.padding = "14px 16px";
  warningNode.style.borderRadius = "16px";
  warningNode.style.background = "rgba(10, 18, 31, 0.96)";
  warningNode.style.border = "1px solid rgba(255,255,255,0.12)";
  warningNode.style.boxShadow = "0 24px 44px rgba(0,0,0,0.35)";
  warningNode.style.color = "#eef5ff";
  warningNode.style.fontFamily = 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif';

  const title = document.createElement("div");
  title.style.fontWeight = "700";
  title.style.marginBottom = "8px";
  title.textContent = analysis.siteType === "sketchy" ? "Do not enter personal info here" : "Leak Prevent warning";

  const body = document.createElement("div");
  body.style.fontSize = "13px";
  body.style.lineHeight = "1.5";
  body.textContent =
    analysis.focusedField?.warning_message ||
    analysis.signals?.[0] ||
    "This field may expose sensitive personal data.";

  const note = document.createElement("div");
  note.style.marginTop = "10px";
  note.style.fontSize = "12px";
  note.style.color = "#98adc5";
  note.textContent = analysis.legalNote || "Open the extension icon for the full context.";

  warningNode.append(title, body, note);

  const settings = await chrome.storage.sync.get({ userEmail: "" });
  const shouldOfferMaskedEmail = isEmailField(analysis.focusedField) || (analysis.dataTypesShared || []).includes("email");

  if (shouldOfferMaskedEmail) {
    const maskedEmail = buildMaskedEmail(settings.userEmail, analysis.domain || location.hostname);
    const emailCard = document.createElement("div");
    emailCard.style.marginTop = "12px";
    emailCard.style.padding = "12px";
    emailCard.style.borderRadius = "12px";
    emailCard.style.background = "rgba(129, 242, 200, 0.08)";
    emailCard.style.border = "1px solid rgba(129, 242, 200, 0.2)";

    const emailTitle = document.createElement("div");
    emailTitle.style.fontSize = "12px";
    emailTitle.style.fontWeight = "700";
    emailTitle.style.marginBottom = "8px";
    emailTitle.textContent = "Masked email";

    const emailValue = document.createElement("div");
    emailValue.style.fontSize = "13px";
    emailValue.style.lineHeight = "1.4";
    emailValue.style.wordBreak = "break-all";
    emailValue.style.marginBottom = "10px";

    const copyButton = document.createElement("button");
    copyButton.type = "button";
    copyButton.style.border = "0";
    copyButton.style.borderRadius = "999px";
    copyButton.style.padding = "8px 12px";
    copyButton.style.fontWeight = "700";
    copyButton.style.cursor = "pointer";
    copyButton.style.background = "linear-gradient(135deg, #81f2c8, #b0ffe3)";
    copyButton.style.color = "#092218";

    if (!settings.userEmail) {
      emailValue.textContent = "Add your real email in Leak Prevent settings to generate site-specific aliases.";
      copyButton.disabled = true;
      copyButton.textContent = "Set email first";
      copyButton.style.opacity = "0.6";
      copyButton.style.cursor = "default";
    } else if (!maskedEmail?.supported || !maskedEmail?.value) {
      emailValue.textContent = maskedEmail?.reason || "This inbox provider does not support an automatic masked alias here.";
      copyButton.disabled = true;
      copyButton.textContent = "Alias unavailable";
      copyButton.style.opacity = "0.6";
      copyButton.style.cursor = "default";
    } else {
      emailValue.textContent = maskedEmail.value;
      copyButton.textContent = "Copy masked email";
      copyButton.addEventListener("click", async () => {
        const copied = await copyToClipboard(maskedEmail.value);
        copyButton.textContent = copied ? "Copied" : "Copy failed";
      });
    }

    emailCard.append(emailTitle, emailValue, copyButton);
    warningNode.append(emailCard);
  }

  document.documentElement.appendChild(warningNode);

  warningTimeout = window.setTimeout(() => {
    hideWarning();
  }, 12000);
}

async function analyzePage(focusedField = null) {
  const payload = buildSnapshot(focusedField);
  const response = await chrome.runtime.sendMessage({
    type: "ANALYZE_PAGE",
    payload,
  });

  if (response?.shouldAutoWarn) {
    showWarning(response).catch(() => undefined);
  } else {
    hideWarning();
  }
}

document.addEventListener(
  "focusin",
  (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement || target instanceof HTMLSelectElement)) {
      return;
    }

    const field = serializeField(target);
    const fingerprint = JSON.stringify(field);
    if (fingerprint === lastFocusedFingerprint) {
      return;
    }

    lastFocusedFingerprint = fingerprint;
    analyzePage(field).catch(() => undefined);
  },
  true
);

window.addEventListener("message", (event) => {
  if (event.source !== window) return;

  if (event.data?.type === "PRIVASEE_EXTENSION_PING") {
    window.postMessage({ type: "PRIVASEE_EXTENSION_PONG", installed: true }, "*");
  }

  if (event.data?.type === "PRIVASEE_OPEN_PANEL") {
    chrome.runtime.sendMessage({ type: "OPEN_SIDE_PANEL_FROM_PAGE" }, (response) => {
      if (chrome.runtime.lastError) return;
      if (response?.ok) {
        window.postMessage({ type: "PRIVASEE_PANEL_OPENED" }, "*");
      }
    });
  }
});

analyzePage().catch(() => undefined);
