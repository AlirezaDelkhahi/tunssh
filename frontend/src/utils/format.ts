export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB", "TB"] as const;
  let value = bytes;
  let unitIdx = 0;
  while (value >= 1024 && unitIdx < units.length - 1) {
    value /= 1024;
    unitIdx += 1;
  }
  const decimals = unitIdx === 0 ? 0 : value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(decimals)} ${units[unitIdx]}`;
}

export function formatRate(bytesPerSec: number): string {
  if (!Number.isFinite(bytesPerSec) || bytesPerSec <= 0) {
    return "0 KB/s";
  }
  if (bytesPerSec < 1024) {
    return `${Math.round(bytesPerSec)} B/s`;
  }
  const kb = bytesPerSec / 1024;
  if (kb < 1024) {
    const decimals = kb >= 100 ? 0 : kb >= 10 ? 1 : 1;
    return `${kb.toFixed(decimals)} KB/s`;
  }
  const mb = kb / 1024;
  const decimals = mb >= 100 ? 0 : mb >= 10 ? 1 : 2;
  return `${mb.toFixed(decimals)} MB/s`;
}

export function formatDuration(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds <= 0) {
    return "00:00:00";
  }
  const clamped = Math.floor(totalSeconds);
  const hours = Math.floor(clamped / 3600);
  const minutes = Math.floor((clamped % 3600) / 60);
  const seconds = clamped % 60;
  return [hours, minutes, seconds]
    .map((part) => String(part).padStart(2, "0"))
    .join(":");
}

export function formatLogTime(isoTimestamp: string): string {
  if (!isoTimestamp) {
    return "--:--:--";
  }
  const date = new Date(isoTimestamp);
  if (Number.isNaN(date.getTime())) {
    return isoTimestamp.slice(11, 19) || isoTimestamp;
  }
  return date.toTimeString().slice(0, 8);
}

export interface PassphraseStrength {
  score: 0 | 1 | 2 | 3 | 4;
  label: "Empty" | "Weak" | "Fair" | "Good" | "Strong";
  colorToken: "muted" | "error" | "warn" | "accent" | "success";
}

export function evaluatePassphraseStrength(
  passphrase: string,
): PassphraseStrength {
  if (!passphrase) {
    return { score: 0, label: "Empty", colorToken: "muted" };
  }
  let points = 0;
  if (passphrase.length >= 8) points += 1;
  if (passphrase.length >= 12) points += 1;
  if (/[a-z]/.test(passphrase) && /[A-Z]/.test(passphrase)) points += 1;
  if (/\d/.test(passphrase)) points += 1;
  if (/[^A-Za-z0-9]/.test(passphrase)) points += 1;

  if (passphrase.length < 6 || points <= 1) {
    return { score: 1, label: "Weak", colorToken: "error" };
  }
  if (points === 2) {
    return { score: 2, label: "Fair", colorToken: "warn" };
  }
  if (points === 3 || points === 4) {
    return { score: 3, label: "Good", colorToken: "accent" };
  }
  return { score: 4, label: "Strong", colorToken: "success" };
}

export async function copyToClipboard(text: string): Promise<boolean> {
  if (!text) {
    return false;
  }
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Fallback below for webviews without navigator.clipboard permission.
  }

  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.setAttribute("readonly", "true");
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    textarea.style.pointerEvents = "none";
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(textarea);
    return ok;
  } catch {
    return false;
  }
}
