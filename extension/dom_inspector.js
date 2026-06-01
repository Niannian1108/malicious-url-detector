const BRAND_DOMAIN_MAP = {
  google: ["google.com", "googleapis.com", "googleusercontent.com", "withgoogle.com"],
  github: ["github.com", "githubusercontent.com", "githubassets.com"],
  microsoft: ["microsoft.com", "live.com", "office.com", "microsoftonline.com", "windows.com"],
  apple: ["apple.com", "icloud.com"],
  paypal: ["paypal.com"],
  dropbox: ["dropbox.com", "dropboxapi.com"],
  adobe: ["adobe.com"],
  amazon: ["amazon.com", "amazonpay.com"],
  aws: ["amazon.com", "aws.amazon.com"],
  atlassian: ["atlassian.com"],
};

const SUSPICIOUS_TERMS = [
  "login",
  "sign in",
  "verify",
  "secure",
  "security",
  "account",
  "update",
  "confirm",
  "password",
  "wallet",
  "billing",
];

function hostnameMatches(candidateDomain) {
  const host = window.location.hostname.toLowerCase();
  return host === candidateDomain || host.endsWith(`.${candidateDomain}`);
}

function countHiddenIframes() {
  return Array.from(document.querySelectorAll("iframe")).filter((iframe) => {
    const rect = iframe.getBoundingClientRect();
    const style = window.getComputedStyle(iframe);
    return (
      rect.width <= 1 ||
      rect.height <= 1 ||
      style.display === "none" ||
      style.visibility === "hidden" ||
      Number(style.opacity) === 0
    );
  }).length;
}

function countExternalScripts() {
  return Array.from(document.scripts).filter((script) => {
    if (!script.src) return false;
    try {
      return new URL(script.src, window.location.href).hostname !== window.location.hostname;
    } catch (error) {
      return false;
    }
  }).length;
}

function computeSuspiciousTextSignals() {
  const bodyText = (document.body?.innerText || "").toLowerCase().slice(0, 50000);
  let suspiciousTextHitCount = 0;
  const presentBrands = new Set();

  for (const term of SUSPICIOUS_TERMS) {
    if (bodyText.includes(term)) {
      suspiciousTextHitCount += 1;
    }
  }

  for (const brand of Object.keys(BRAND_DOMAIN_MAP)) {
    if (bodyText.includes(brand)) {
      presentBrands.add(brand);
    }
  }

  let pageBrandMismatch = 0;
  for (const brand of presentBrands) {
    const approvedDomains = BRAND_DOMAIN_MAP[brand];
    if (!approvedDomains.some(hostnameMatches)) {
      pageBrandMismatch = 1;
      break;
    }
  }

  return { suspiciousTextHitCount, pageBrandMismatch };
}

function collectDomSignals() {
  const { suspiciousTextHitCount, pageBrandMismatch } = computeSuspiciousTextSignals();
  return {
    form_count: document.forms.length,
    password_field_count: document.querySelectorAll('input[type="password"]').length,
    hidden_iframe_count: countHiddenIframes(),
    external_script_count: countExternalScripts(),
    suspicious_text_hit_count: suspiciousTextHitCount,
    page_brand_mismatch: pageBrandMismatch,
  };
}

function shouldSkipCurrentPage() {
  return (
    window.location.protocol !== "http:" &&
    window.location.protocol !== "https:"
  );
}

function showCautionBanner(message) {
  const existing = document.getElementById("malicious-url-detector-caution");
  if (existing) {
    existing.remove();
  }

  const confidence = Number(message.confidence);
  const confidenceLabel = Number.isFinite(confidence)
    ? `${Math.round(confidence * 100)}%`
    : "elevated";
  const reasons = Array.isArray(message.reasons) && message.reasons.length
    ? message.reasons
    : ["This page matched suspicious URL or page signals."];

  const banner = document.createElement("div");
  banner.id = "malicious-url-detector-caution";
  banner.style.cssText = [
    "position: fixed",
    "left: 16px",
    "right: 16px",
    "bottom: 16px",
    "z-index: 2147483647",
    "box-sizing: border-box",
    "max-width: 760px",
    "margin: 0 auto",
    "padding: 14px 16px",
    "border: 1px solid rgba(146, 64, 14, 0.35)",
    "border-radius: 8px",
    "background: #fff7ed",
    "color: #1c1917",
    "box-shadow: 0 16px 40px rgba(28, 25, 23, 0.18)",
    "font: 14px/1.45 Georgia, 'Times New Roman', serif",
  ].join(";");

  const title = document.createElement("div");
  title.textContent = `Caution: this page looks suspicious (${confidenceLabel} confidence)`;
  title.style.cssText = "font-weight: 700; margin-bottom: 6px;";

  const reasonText = document.createElement("div");
  reasonText.textContent = reasons.slice(0, 2).join(" ");
  reasonText.style.cssText = "padding-right: 32px;";

  const closeButton = document.createElement("button");
  closeButton.type = "button";
  closeButton.textContent = "Dismiss";
  closeButton.style.cssText = [
    "position: absolute",
    "right: 10px",
    "top: 10px",
    "border: 1px solid rgba(146, 64, 14, 0.35)",
    "border-radius: 6px",
    "background: #ffffff",
    "color: #1c1917",
    "padding: 4px 8px",
    "font: inherit",
    "cursor: pointer",
  ].join(";");
  closeButton.addEventListener("click", () => banner.remove());

  banner.append(title, reasonText, closeButton);
  document.documentElement.appendChild(banner);
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "show-caution-banner") {
    showCautionBanner(message);
    sendResponse({ ok: true });
    return false;
  }

  return false;
});

if (!shouldSkipCurrentPage()) {
  window.addEventListener("load", () => {
    try {
      chrome.runtime.sendMessage({
        type: "dom-ready",
        url: window.location.href,
      });

      chrome.runtime.sendMessage({
        type: "analyze-page-dom",
        url: window.location.href,
        domSignals: collectDomSignals(),
      });
    } catch (error) {
      console.warn("[Malicious URL Detector] DOM inspection message failed:", error);
    }
  }, { once: true });
}
