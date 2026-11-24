import { useEffect, useRef, useState, type FormEvent } from "react";
import type { ProfileView, ShareInspectDTO } from "../api/bridge";
import { formatBridgeError } from "../api/bridge";
import { copyToClipboard, evaluatePassphraseStrength } from "../utils/format";
import {
  AlertTriangleIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CloseIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  LockIcon,
  ShareIcon,
  ShieldCheckIcon,
} from "./Icons";

interface ShareModalProps {
  open: boolean;
  profiles: ProfileView[];
  activeProfileId: string;
  onClose: () => void;
  onExport: (
    profileID: string,
    passphrase: string,
    unsafePlain: boolean,
  ) => Promise<string>;
  onInspect: (link: string) => Promise<ShareInspectDTO>;
  onImport: (
    link: string,
    passphrase: string,
    allowPlain: boolean,
  ) => Promise<ProfileView>;
}

export function ShareModal({
  open,
  profiles,
  activeProfileId,
  onClose,
  onExport,
  onInspect,
  onImport,
}: ShareModalProps) {
  const [tab, setTab] = useState<"export" | "import">("export");

  // Export state
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [showExportPass, setShowExportPass] = useState(false);
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [plainRiskAccepted, setPlainRiskAccepted] = useState(false);
  const [exportBusy, setExportBusy] = useState(false);
  const [generatedLink, setGeneratedLink] = useState("");
  const [generatedCopied, setGeneratedCopied] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  // Import state
  const [importLink, setImportLink] = useState("");
  const [inspectMeta, setInspectMeta] = useState<ShareInspectDTO | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [importPassphrase, setImportPassphrase] = useState("");
  const [showImportPass, setShowImportPass] = useState(false);
  const [allowPlainImport, setAllowPlainImport] = useState(false);
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);

  const importTextareaRef = useRef<HTMLTextAreaElement>(null);
  const onInspectRef = useRef(onInspect);
  onInspectRef.current = onInspect;
  const lastInspectedLinkRef = useRef("");

  useEffect(() => {
    if (!open) {
      return;
    }
    setTab(profiles.length > 0 ? "export" : "import");
    setSelectedProfileId(activeProfileId || profiles[0]?.id || "");
    setExportPassphrase("");
    setShowExportPass(false);
    setAdvancedOpen(false);
    setPlainRiskAccepted(false);
    setGeneratedLink("");
    setGeneratedCopied(false);
    setExportError(null);

    setImportLink("");
    lastInspectedLinkRef.current = "";
    setInspectMeta(null);
    setInspecting(false);
    setImportPassphrase("");
    setShowImportPass(false);
    setAllowPlainImport(false);
    setImportError(null);
    // Initialize modal state once when opened so background profile updates do not wipe input.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !exportBusy && !importBusy) {
        onClose();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, exportBusy, importBusy, onClose]);

  useEffect(() => {
    if (!generatedCopied) {
      return undefined;
    }
    const timer = window.setTimeout(() => setGeneratedCopied(false), 2200);
    return () => window.clearTimeout(timer);
  }, [generatedCopied]);

  useEffect(() => {
    if (!open || tab !== "import") {
      return undefined;
    }
    const trimmed = importLink.trim();
    if (!trimmed) {
      lastInspectedLinkRef.current = "";
      setInspectMeta(null);
      setAllowPlainImport(false);
      setImportError(null);
      return undefined;
    }
    if (!trimmed.startsWith("sshtun://v1/")) {
      lastInspectedLinkRef.current = "";
      setInspectMeta(null);
      setAllowPlainImport(false);
      setImportError("Share link must start with sshtun://v1/");
      return undefined;
    }

    let cancelled = false;
    setInspecting(true);
    setImportError(null);
    const timer = window.setTimeout(async () => {
      try {
        const meta = await onInspectRef.current(trimmed);
        if (!cancelled) {
          if (lastInspectedLinkRef.current !== trimmed) {
            setAllowPlainImport(false);
            lastInspectedLinkRef.current = trimmed;
          }
          setInspectMeta(meta);
        }
      } catch (err) {
        if (!cancelled) {
          lastInspectedLinkRef.current = "";
          setInspectMeta(null);
          setImportError(formatBridgeError(err));
        }
      } finally {
        if (!cancelled) {
          setInspecting(false);
        }
      }
    }, 180);

    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [open, tab, importLink]);

  if (!open) {
    return null;
  }

  const strength = evaluatePassphraseStrength(exportPassphrase);

  const handleExportSubmit = async (unsafePlain: boolean) => {
    if (!selectedProfileId) {
      setExportError("Select a profile to export.");
      return;
    }
    if (!unsafePlain && !exportPassphrase) {
      setExportError("Enter an encryption passphrase before generating a link.");
      return;
    }
    if (unsafePlain && !plainRiskAccepted) {
      setExportError(
        "Confirm the unencrypted share risk checkbox before copying.",
      );
      return;
    }

    setExportBusy(true);
    setExportError(null);
    try {
      const link = await onExport(
        selectedProfileId,
        unsafePlain ? "" : exportPassphrase,
        unsafePlain,
      );
      setGeneratedLink(link);
      const copied = await copyToClipboard(link);
      setGeneratedCopied(copied);
    } catch (err) {
      setExportError(formatBridgeError(err));
    } finally {
      setExportBusy(false);
    }
  };

  const handleImportSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = importLink.trim();
    if (!trimmed) {
      setImportError("Paste an sshtun://v1/... link first.");
      return;
    }
    if (!inspectMeta) {
      setImportError("Wait for link verification or fix the link format.");
      return;
    }
    if (inspectMeta.mode === "enc" && !importPassphrase) {
      setImportError("Enter the share link passphrase to decrypt.");
      return;
    }
    if (inspectMeta.mode === "plain" && !allowPlainImport) {
      setImportError(
        "Confirm that you understand this unencrypted link exposes credentials in plaintext.",
      );
      return;
    }

    setImportBusy(true);
    setImportError(null);
    try {
      await onImport(
        trimmed,
        inspectMeta.mode === "enc" ? importPassphrase : "",
        inspectMeta.mode === "plain" ? allowPlainImport : false,
      );
      onClose();
    } catch (err) {
      setImportError(formatBridgeError(err));
    } finally {
      setImportBusy(false);
    }
  };

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !exportBusy && !importBusy) {
          onClose();
        }
      }}
    >
      <div
        className="modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="share-modal-title"
      >
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge-icon badge-icon--blue">
              <ShareIcon size={15} />
            </span>
            <div>
              <h2 id="share-modal-title" className="modal-title">
                Share &amp; Import Profile
              </h2>
              <p className="modal-subtitle">
                Portable <code dir="ltr">sshtun://v1/...</code> links with TOFU host-key pinning
              </p>
            </div>
          </div>
          <button
            type="button"
            className="icon-btn icon-btn--ghost"
            onClick={onClose}
            disabled={exportBusy || importBusy}
            aria-label="Close modal"
          >
            <CloseIcon size={15} />
          </button>
        </div>

        <div className="modal-tabs" role="tablist" aria-label="Share actions">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "export"}
            className={`modal-tab ${tab === "export" ? "is-active" : ""}`}
            onClick={() => setTab("export")}
          >
            Export Link
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "import"}
            className={`modal-tab ${tab === "import" ? "is-active" : ""}`}
            onClick={() => {
              setTab("import");
              window.setTimeout(() => importTextareaRef.current?.focus(), 20);
            }}
          >
            Import Link
          </button>
        </div>

        {tab === "export" ? (
          <div className="modal-body modal-body--scroll" role="tabpanel">
            {profiles.length === 0 ? (
              <div className="empty-box">
                Create a profile first before exporting a share link.
              </div>
            ) : (
              <>
                <div className="field">
                  <label htmlFor="share-export-profile" className="field__label">
                    Profile to Share
                  </label>
                  <select
                    id="share-export-profile"
                    className="input"
                    value={selectedProfileId}
                    onChange={(e) => {
                      setSelectedProfileId(e.target.value);
                      setGeneratedLink("");
                    }}
                  >
                    {profiles.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.name} ({p.host}:{p.port})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="field">
                  <div className="field__label-row">
                    <label htmlFor="share-export-pass" className="field__label">
                      Encryption Passphrase (Argon2id + AES-256-GCM)
                    </label>
                    <span className={`strength-label strength-label--${strength.colorToken}`}>
                      {strength.label}
                    </span>
                  </div>
                  <div className="input-with-addon">
                    <input
                      id="share-export-pass"
                      type={showExportPass ? "text" : "password"}
                      className="input"
                      value={exportPassphrase}
                      onChange={(e) => setExportPassphrase(e.target.value)}
                      placeholder="Choose a passphrase to share separately"
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      className="input-addon-btn"
                      onClick={() => setShowExportPass((v) => !v)}
                      aria-label={showExportPass ? "Hide passphrase" : "Show passphrase"}
                    >
                      {showExportPass ? <EyeOffIcon size={15} /> : <EyeIcon size={15} />}
                    </button>
                  </div>

                  <div className="strength-meter" aria-hidden="true">
                    {[1, 2, 3, 4].map((step) => (
                      <span
                        key={step}
                        className={`strength-meter__bar ${
                          strength.score >= step ? `is-${strength.colorToken}` : ""
                        }`}
                      />
                    ))}
                  </div>
                </div>

                <button
                  type="button"
                  className="btn btn--primary btn--full"
                  disabled={exportBusy || !exportPassphrase}
                  onClick={() => handleExportSubmit(false)}
                >
                  <LockIcon size={14} />
                  <span>
                    {exportBusy ? "Encrypting Link..." : "Copy Encrypted Link"}
                  </span>
                </button>

                {generatedLink && (
                  <div className="share-result">
                    <div className="share-result__top">
                      <span className="share-result__status">
                        <CheckIcon size={13} />
                        <span>
                          {generatedCopied
                            ? "Link copied to clipboard"
                            : "Share link generated"}
                        </span>
                      </span>
                      <button
                        type="button"
                        className="copy-pill"
                        onClick={async () => {
                          if (await copyToClipboard(generatedLink)) {
                            setGeneratedCopied(true);
                          }
                        }}
                      >
                        <CopyIcon size={11} />
                        <span>Copy</span>
                      </button>
                    </div>
                    <code className="share-result__preview" dir="ltr">
                      {generatedLink.slice(0, 56)}...
                    </code>
                  </div>
                )}

                <div className="advanced-box">
                  <button
                    type="button"
                    className="advanced-box__toggle"
                    onClick={() => setAdvancedOpen((v) => !v)}
                    aria-expanded={advancedOpen}
                  >
                    <span>Advanced: Unencrypted Quick-Share</span>
                    {advancedOpen ? (
                      <ChevronUpIcon size={14} />
                    ) : (
                      <ChevronDownIcon size={14} />
                    )}
                  </button>

                  {advancedOpen && (
                    <div className="advanced-box__body">
                      <div className="inline-alert inline-alert--error">
                        <label className="checkbox-row checkbox-row--danger">
                          <input
                            type="checkbox"
                            checked={plainRiskAccepted}
                            onChange={(e) =>
                              setPlainRiskAccepted(e.target.checked)
                            }
                          />
                          <span>
                            Anyone who reads this link (chat history, clipboard,
                            ISP) can read your VPS password/private key!
                          </span>
                        </label>
                      </div>
                      <button
                        type="button"
                        className="btn btn--danger-outline btn--full btn--sm"
                        disabled={exportBusy || !plainRiskAccepted}
                        onClick={() => handleExportSubmit(true)}
                      >
                        <AlertTriangleIcon size={13} />
                        <span>Copy Unencrypted Link</span>
                      </button>
                    </div>
                  )}
                </div>

                {exportError && (
                  <div className="inline-alert inline-alert--error" role="alert">
                    {exportError}
                  </div>
                )}
              </>
            )}
          </div>
        ) : (
          <form className="modal-body modal-body--scroll" onSubmit={handleImportSubmit} role="tabpanel">
            <div className="field">
              <label htmlFor="share-import-link" className="field__label">
                Paste Share Link
              </label>
              <textarea
                ref={importTextareaRef}
                id="share-import-link"
                className="textarea textarea--mono"
                dir="ltr"
                rows={3}
                value={importLink}
                onChange={(e) => setImportLink(e.target.value)}
                placeholder="sshtun://v1/..."
                spellCheck={false}
              />
            </div>

            {inspecting && (
              <div className="helper-note">Inspecting link envelope...</div>
            )}

            {inspectMeta && (
              <div className="inspect-card">
                <div className="inspect-card__row">
                  <span className="mini-tag" dir="ltr">
                    v{inspectMeta.version}
                  </span>
                  {inspectMeta.mode === "enc" ? (
                    <span className="status-badge status-badge--ok">
                      <LockIcon size={12} />
                      <span>Encrypted (Argon2id + AES-GCM)</span>
                    </span>
                  ) : (
                    <span className="status-badge status-badge--danger">
                      <AlertTriangleIcon size={12} />
                      <span>Unencrypted Plaintext</span>
                    </span>
                  )}
                </div>

                <div className="inspect-card__hostkey">
                  <ShieldCheckIcon size={13} />
                  <span>
                    {inspectMeta.mode === "enc"
                      ? "Encrypted payload — host key status verified after decryption"
                      : inspectMeta.has_host_key
                        ? "Includes pinned SSH host key (TOFU protected)"
                        : "No pinned host key included — will prompt on first connect"}
                  </span>
                </div>
              </div>
            )}

            {inspectMeta?.mode === "enc" && (
              <div className="field">
                <label htmlFor="share-import-pass" className="field__label">
                  Decryption Passphrase
                </label>
                <div className="input-with-addon">
                  <input
                    id="share-import-pass"
                    type={showImportPass ? "text" : "password"}
                    className="input"
                    value={importPassphrase}
                    onChange={(e) => setImportPassphrase(e.target.value)}
                    placeholder="Enter passphrase from link sender"
                    autoComplete="off"
                  />
                  <button
                    type="button"
                    className="input-addon-btn"
                    onClick={() => setShowImportPass((v) => !v)}
                    aria-label={showImportPass ? "Hide passphrase" : "Show passphrase"}
                  >
                    {showImportPass ? <EyeOffIcon size={15} /> : <EyeIcon size={15} />}
                  </button>
                </div>
              </div>
            )}

            {inspectMeta?.mode === "plain" && (
              <div className="inline-alert inline-alert--error">
                <label className="checkbox-row checkbox-row--danger">
                  <input
                    type="checkbox"
                    checked={allowPlainImport}
                    onChange={(e) => setAllowPlainImport(e.target.checked)}
                  />
                  <span>
                    Warning: This link is unencrypted. Confirm to import plaintext
                    credentials into your vault.
                  </span>
                </label>
              </div>
            )}

            {importError && (
              <div className="inline-alert inline-alert--error" role="alert">
                {importError}
              </div>
            )}

            <div className="modal-footer modal-footer--end">
              <button
                type="button"
                className="btn btn--ghost"
                onClick={onClose}
                disabled={importBusy}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn--primary"
                disabled={
                  importBusy ||
                  !inspectMeta ||
                  (inspectMeta.mode === "enc" && !importPassphrase) ||
                  (inspectMeta.mode === "plain" && !allowPlainImport)
                }
              >
                {importBusy ? "Importing..." : "Import Profile"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
