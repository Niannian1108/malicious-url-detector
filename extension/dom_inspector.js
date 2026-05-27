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

if (!shouldSkipCurrentPage()) {
  window.addEventListener("load", () => {
    try {
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
