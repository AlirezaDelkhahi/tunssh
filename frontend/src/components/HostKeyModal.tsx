import { useEffect, useRef, useState } from "react";
import type { HostKeyPromptDTO } from "../api/bridge";
import { copyToClipboard } from "../utils/format";
import {
  CheckIcon,
  CopyIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
} from "./Icons";

interface HostKeyModalProps {
  prompt: HostKeyPromptDTO | null;
  busy: boolean;
  onTrustAndConnect: (prompt: HostKeyPromptDTO) => Promise<void>;
  onForgetAndReconnect: (prompt: HostKeyPromptDTO) => Promise<void>;
  onCancel: () => void;
}

export function HostKeyModal({
  prompt,
  busy,
  onTrustAndConnect,
  onForgetAndReconnect,
  onCancel,
}: HostKeyModalProps) {
  const [copiedFp, setCopiedFp] = useState(false);
  const safeDefaultBtnRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!prompt) {
      return undefined;
    }
    setCopiedFp(false);
    const focusTimer = window.setTimeout(() => {
      safeDefaultBtnRef.current?.focus();
    }, 20);

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) {
        onCancel();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      window.clearTimeout(focusTimer);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [prompt, busy, onCancel]);

  useEffect(() => {
    if (!copiedFp) {
      return undefined;
    }
    const timer = window.setTimeout(() => setCopiedFp(false), 1800);
    return () => window.clearTimeout(timer);
  }, [copiedFp]);

  if (!prompt) {
    return null;
  }

  const handleCopy = async () => {
    if (await copyToClipboard(prompt.sha256)) {
      setCopiedFp(true);
    }
  };

  if (prompt.is_mismatch) {
    return (
      <div className="modal-backdrop" role="presentation">
        <div
          className="modal-card modal-card--danger"
          role="alertdialog"
          aria-modal="true"
          aria-labelledby="hostkey-modal-title"
          aria-describedby="hostkey-modal-desc"
        >
          <div className="modal-header">
            <div className="modal-title-group">
              <span className="badge-icon badge-icon--danger">
                <ShieldAlertIcon size={17} />
              </span>
              <div>
                <h2 id="hostkey-modal-title" className="modal-title modal-title--danger">
                  Host Key Mismatch — Possible MITM
                </h2>
                <p className="modal-subtitle" dir="ltr">
                  {prompt.host}:{prompt.port}
                </p>
              </div>
            </div>
          </div>

          <div className="modal-body modal-body--scroll">
            <div id="hostkey-modal-desc" className="inline-alert inline-alert--error">
              The remote SSH server presented a different host key than the one
              pinned for this profile. Do NOT re-trust unless you intentionally
              rebuilt or rotated keys on your VPS.
            </div>

            <div className="fp-compare">
              <div className="fp-box fp-box--expected">
                <div className="fp-box__header">
                  <span>Expected SHA-256 (Pinned)</span>
                  <span className="mini-tag" dir="ltr">
                    {prompt.expected_algorithm || "unknown"}
                  </span>
                </div>
                <code className="fp-box__value" dir="ltr">
                  {prompt.expected_sha256 || "Unavailable"}
                </code>
              </div>

              <div className="fp-box fp-box--received">
                <div className="fp-box__header">
                  <span>Received SHA-256 (Remote)</span>
                  <span className="mini-tag mini-tag--danger" dir="ltr">
                    {prompt.algorithm}
                  </span>
                </div>
                <code className="fp-box__value" dir="ltr">
                  {prompt.sha256}
                </code>
              </div>
            </div>

            <div className="modal-footer modal-footer--stack">
              <button
                ref={safeDefaultBtnRef}
                type="button"
                className="btn btn--primary btn--full"
                onClick={onCancel}
                disabled={busy}
              >
                Abort Connection
              </button>
              <button
                type="button"
                className="btn btn--danger-outline btn--full"
                onClick={() => onForgetAndReconnect(prompt)}
                disabled={busy}
              >
                {busy ? "Resetting Pin..." : "Forget & Re-trust Host Key"}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="modal-backdrop" role="presentation">
      <div
        className="modal-card modal-card--compact"
        role="dialog"
        aria-modal="true"
        aria-labelledby="hostkey-modal-title"
      >
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge-icon badge-icon--emerald">
              <ShieldCheckIcon size={17} />
            </span>
            <div>
              <h2 id="hostkey-modal-title" className="modal-title">
                Verify Server Host Key
              </h2>
              <p className="modal-subtitle" dir="ltr">
                {prompt.host}:{prompt.port}
              </p>
            </div>
          </div>
        </div>

        <div className="modal-body modal-body--scroll">
          <p className="helper-note">
            First time connecting to this server. Confirm the SHA-256 fingerprint
            matches your VPS before pinning it for future connections.
          </p>

          <div className="fp-box">
            <div className="fp-box__header">
              <span>Algorithm: <strong dir="ltr">{prompt.algorithm}</strong></span>
              <button
                type="button"
                className={`copy-pill ${copiedFp ? "is-copied" : ""}`}
                onClick={handleCopy}
              >
                {copiedFp ? <CheckIcon size={11} /> : <CopyIcon size={11} />}
                <span>{copiedFp ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <code className="fp-box__value" dir="ltr">
              {prompt.sha256}
            </code>
          </div>

          <div className="modal-footer modal-footer--end">
            <button
              type="button"
              className="btn btn--ghost"
              onClick={onCancel}
              disabled={busy}
            >
              Cancel
            </button>
            <button
              ref={safeDefaultBtnRef}
              type="button"
              className="btn btn--primary"
              onClick={() => onTrustAndConnect(prompt)}
              disabled={busy}
            >
              <ShieldCheckIcon size={14} />
              <span>{busy ? "Pinning..." : "Trust & Connect"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
