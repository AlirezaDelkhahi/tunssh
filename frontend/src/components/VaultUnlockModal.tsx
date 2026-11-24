import { useEffect, useRef, useState, type FormEvent } from "react";
import { EyeIcon, EyeOffIcon, LockIcon } from "./Icons";

interface VaultUnlockModalProps {
  open: boolean;
  onUnlock: (passphrase: string) => Promise<void>;
}

export function VaultUnlockModal({ open, onUnlock }: VaultUnlockModalProps) {
  const [passphrase, setPassphrase] = useState("");
  const [showPassphrase, setShowPassphrase] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setError(null);
      setPassphrase("");
      const id = window.setTimeout(() => inputRef.current?.focus(), 30);
      return () => window.clearTimeout(id);
    }
    return undefined;
  }, [open]);

  if (!open) {
    return null;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!passphrase) {
      setError("Enter your local vault passphrase.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onUnlock(passphrase);
      setPassphrase("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop" role="presentation">
      <div
        className="modal-card modal-card--compact"
        role="dialog"
        aria-modal="true"
        aria-labelledby="vault-unlock-title"
      >
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge-icon badge-icon--blue">
              <LockIcon size={16} />
            </span>
            <div>
              <h2 id="vault-unlock-title" className="modal-title">
                Unlock Local Vault
              </h2>
              <p className="modal-subtitle">
                Encrypted credential storage (<code dir="ltr">secrets.enc</code>)
              </p>
            </div>
          </div>
        </div>

        <form className="modal-body modal-body--scroll" onSubmit={handleSubmit}>
          <p className="helper-note">
            No OS keyring service is available in this desktop session. Enter your
            local vault passphrase to unlock saved SSH passwords and private keys in
            memory.
          </p>

          <div className="field">
            <label htmlFor="vault-passphrase" className="field__label">
              Vault Passphrase
            </label>
            <div className="input-with-addon">
              <input
                ref={inputRef}
                id="vault-passphrase"
                type={showPassphrase ? "text" : "password"}
                className="input"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter passphrase for secrets.enc"
                autoComplete="current-password"
                disabled={submitting}
              />
              <button
                type="button"
                className="input-addon-btn"
                onClick={() => setShowPassphrase((v) => !v)}
                aria-label={showPassphrase ? "Hide passphrase" : "Show passphrase"}
              >
                {showPassphrase ? <EyeOffIcon size={15} /> : <EyeIcon size={15} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="inline-alert inline-alert--error" role="alert">
              {error}
            </div>
          )}

          <div className="modal-footer modal-footer--end">
            <button
              type="submit"
              className="btn btn--primary btn--full"
              disabled={submitting || !passphrase}
            >
              {submitting ? "Decrypting Vault..." : "Unlock Vault"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
