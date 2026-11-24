import { useEffect, useRef, useState, type FormEvent } from "react";
import type { ProfileView, SaveProfileRequest } from "../api/bridge";
import { formatBridgeError } from "../api/bridge";
import {
  CloseIcon,
  EyeIcon,
  EyeOffIcon,
  FolderOpenIcon,
  KeyIcon,
  LockIcon,
  ShieldCheckIcon,
  TrashIcon,
} from "./Icons";

interface ProfileModalProps {
  open: boolean;
  profile: ProfileView | null;
  onClose: () => void;
  onSave: (req: SaveProfileRequest) => Promise<void>;
  onDelete: (profileID: string) => Promise<void>;
  onClearHostKey: (profileID: string) => Promise<ProfileView>;
  onPickPrivateKey: () => Promise<string>;
}

const PORT_PRESETS = [
  { port: 22, label: "22 (Default)" },
  { port: 443, label: "443 (TLS Port)" },
  { port: 2053, label: "2053 (Alt)" },
] as const;

export function ProfileModal({
  open,
  profile,
  onClose,
  onSave,
  onDelete,
  onClearHostKey,
  onPickPrivateKey,
}: ProfileModalProps) {
  const isEdit = Boolean(profile);

  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [portInput, setPortInput] = useState("22");
  const [username, setUsername] = useState("");
  const [authType, setAuthType] = useState<"password" | "key">("password");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [privateKey, setPrivateKey] = useState("");
  const [keyPassphrase, setKeyPassphrase] = useState("");
  const [showKeyPassphrase, setShowKeyPassphrase] = useState(false);
  const [bypassIranLAN, setBypassIranLAN] = useState(true);

  const [saving, setSaving] = useState(false);
  const [clearingKey, setClearingKey] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const nameRef = useRef<HTMLInputElement>(null);

  const profileId = profile?.id ?? null;

  useEffect(() => {
    if (!open) {
      return;
    }
    setError(null);
    setConfirmDelete(false);
    setShowPassword(false);
    setShowKeyPassphrase(false);
    setPassword("");
    setPrivateKey("");
    setKeyPassphrase("");

    if (profile) {
      setName(profile.name);
      setHost(profile.host);
      setPortInput(String(profile.port || 22));
      setUsername(profile.username);
      setAuthType(profile.auth_type);
      setBypassIranLAN(profile.bypass_iran_lan);
    } else {
      setName("");
      setHost("");
      setPortInput("22");
      setUsername("");
      setAuthType("password");
      setBypassIranLAN(true);
    }

    const id = window.setTimeout(() => nameRef.current?.focus(), 20);
    return () => window.clearTimeout(id);
    // Intentionally re-initialize form only when modal opens or switches profile ID.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, profileId]);

  useEffect(() => {
    if (!open) {
      return undefined;
    }
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !saving && !deleting) {
        onClose();
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, saving, deleting, onClose]);

  if (!open) {
    return null;
  }

  const handleBrowseKey = async () => {
    setError(null);
    try {
      const pem = await onPickPrivateKey();
      if (pem) {
        setPrivateKey(pem);
      }
    } catch (err) {
      setError(formatBridgeError(err));
    }
  };

  const handleClearHostKey = async () => {
    if (!profile) {
      return;
    }
    setClearingKey(true);
    setError(null);
    try {
      await onClearHostKey(profile.id);
    } catch (err) {
      setError(formatBridgeError(err));
    } finally {
      setClearingKey(false);
    }
  };

  const handleDelete = async () => {
    if (!profile) {
      return;
    }
    if (!confirmDelete) {
      setConfirmDelete(true);
      return;
    }
    setDeleting(true);
    setError(null);
    try {
      await onDelete(profile.id);
      onClose();
    } catch (err) {
      setError(formatBridgeError(err));
    } finally {
      setDeleting(false);
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmedName = name.trim();
    const trimmedHost = host.trim();
    const trimmedUser = username.trim();
    const parsedPort = Number.parseInt(portInput, 10);

    if (!trimmedName) {
      setError("Profile name is required.");
      return;
    }
    if (!trimmedHost) {
      setError("Host or IP address is required.");
      return;
    }
    if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
      setError("Port must be a number between 1 and 65535.");
      return;
    }
    if (!trimmedUser) {
      setError("SSH username is required.");
      return;
    }

    const sameAuthType = Boolean(profile && profile.auth_type === authType);
    const hasExistingSecret = Boolean(profile?.has_secret && sameAuthType);

    let keepExistingSecrets = false;

    if (authType === "password") {
      if (password.length > 0) {
        keepExistingSecrets = false;
      } else if (hasExistingSecret) {
        keepExistingSecrets = true;
      } else {
        setError("Password is required for Password / PAM authentication.");
        return;
      }
    } else {
      const hasNewKey = privateKey.trim().length > 0;
      if (hasNewKey) {
        keepExistingSecrets = false;
      } else if (hasExistingSecret && keyPassphrase.length === 0) {
        keepExistingSecrets = true;
      } else if (hasExistingSecret && keyPassphrase.length > 0) {
        setError(
          "Paste the SSH private key when setting a new key passphrase.",
        );
        return;
      } else {
        setError("SSH private key (PEM / OpenSSH format) is required.");
        return;
      }
    }

    const req: SaveProfileRequest = {
      id: profile?.id,
      name: trimmedName,
      host: trimmedHost,
      port: parsedPort,
      username: trimmedUser,
      auth_type: authType,
      bypass_iran_lan: bypassIranLAN,
      preferred_mode: profile?.preferred_mode ?? "proxy",
      password: authType === "password" && !keepExistingSecrets ? password : "",
      private_key:
        authType === "key" && !keepExistingSecrets ? privateKey.trim() : "",
      key_passphrase:
        authType === "key" && !keepExistingSecrets ? keyPassphrase : "",
      keep_existing_secrets: keepExistingSecrets,
    };

    setSaving(true);
    try {
      await onSave(req);
      onClose();
    } catch (err) {
      setError(formatBridgeError(err));
    } finally {
      setSaving(false);
    }
  };

  const currentPortNum = Number.parseInt(portInput, 10);

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !saving && !deleting) {
          onClose();
        }
      }}
    >
      <div
        className="modal-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="profile-modal-title"
      >
        <div className="modal-header">
          <div className="modal-title-group">
            <span className="badge-icon badge-icon--blue">
              <KeyIcon size={15} />
            </span>
            <div>
              <h2 id="profile-modal-title" className="modal-title">
                {isEdit ? "Edit SSH Profile" : "New SSH Profile"}
              </h2>
              <p className="modal-subtitle">
                Credentials stay strictly inside OS Keyring / encrypted vault
              </p>
            </div>
          </div>
          <button
            type="button"
            className="icon-btn icon-btn--ghost"
            onClick={onClose}
            disabled={saving || deleting}
            aria-label="Close modal"
          >
            <CloseIcon size={15} />
          </button>
        </div>

        <form className="modal-body modal-body--scroll" onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="profile-name" className="field__label">
              Profile Name
            </label>
            <input
              ref={nameRef}
              id="profile-name"
              type="text"
              className="input"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. DE-443"
              maxLength={80}
            />
          </div>

          <div className="field-row">
            <div className="field field--grow">
              <label htmlFor="profile-host" className="field__label">
                Host / IP
              </label>
              <input
                id="profile-host"
                type="text"
                className="input input--mono"
                dir="ltr"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="vps.example.com"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
              />
            </div>

            <div className="field field--port">
              <label htmlFor="profile-port" className="field__label">
                Port
              </label>
              <input
                id="profile-port"
                type="number"
                className="input input--mono"
                dir="ltr"
                min={1}
                max={65535}
                value={portInput}
                onChange={(e) => setPortInput(e.target.value)}
              />
            </div>
          </div>

          <div className="port-hints">
            <div className="port-hints__chips" role="group" aria-label="Quick port presets">
              {PORT_PRESETS.map((preset) => (
                <button
                  key={preset.port}
                  type="button"
                  className={`port-chip ${currentPortNum === preset.port ? "is-active" : ""}`}
                  onClick={() => setPortInput(String(preset.port))}
                >
                  {preset.label}
                </button>
              ))}
            </div>
            <span className="field__hint">
              Iranian ISPs frequently throttle port 22 — ports 443 or 2053 are recommended.
            </span>
          </div>

          <div className="field">
            <label htmlFor="profile-username" className="field__label">
              Username
            </label>
            <input
              id="profile-username"
              type="text"
              className="input input--mono"
              dir="ltr"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="ubuntu"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
            />
          </div>

          <div className="field">
            <span className="field__label">Auth Type</span>
            <div className="segmented segmented--sm" role="radiogroup" aria-label="Authentication method">
              <button
                type="button"
                role="radio"
                aria-checked={authType === "password"}
                className={`segmented__btn ${authType === "password" ? "is-active" : ""}`}
                onClick={() => setAuthType("password")}
              >
                Password / PAM
              </button>
              <button
                type="button"
                role="radio"
                aria-checked={authType === "key"}
                className={`segmented__btn ${authType === "key" ? "is-active" : ""}`}
                onClick={() => setAuthType("key")}
              >
                SSH Key
              </button>
            </div>
          </div>

          {authType === "password" ? (
            <div className="field">
              <label htmlFor="profile-password" className="field__label">
                Password
              </label>
              <div className="input-with-addon">
                <input
                  id="profile-password"
                  type={showPassword ? "text" : "password"}
                  className="input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={
                    profile?.has_secret && profile.auth_type === "password"
                      ? "Stored in vault — leave blank to keep existing"
                      : "Enter SSH / PAM password"
                  }
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  className="input-addon-btn"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOffIcon size={15} /> : <EyeIcon size={15} />}
                </button>
              </div>
            </div>
          ) : (
            <>
              <div className="field">
                <div className="field__label-row">
                  <label htmlFor="profile-private-key" className="field__label">
                    Private Key (PEM / OpenSSH)
                  </label>
                  <button
                    type="button"
                    className="btn btn--xs btn--surface"
                    onClick={handleBrowseKey}
                  >
                    <FolderOpenIcon size={12} />
                    <span>Browse File</span>
                  </button>
                </div>
                <textarea
                  id="profile-private-key"
                  className="textarea textarea--mono"
                  dir="ltr"
                  rows={4}
                  value={privateKey}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  placeholder={
                    profile?.has_secret && profile.auth_type === "key"
                      ? "Private key stored in vault — paste new key or browse file to replace"
                      : "-----BEGIN OPENSSH PRIVATE KEY-----"
                  }
                  spellCheck={false}
                />
              </div>

              <div className="field">
                <label htmlFor="profile-key-passphrase" className="field__label">
                  Key Passphrase (Optional)
                </label>
                <div className="input-with-addon">
                  <input
                    id="profile-key-passphrase"
                    type={showKeyPassphrase ? "text" : "password"}
                    className="input"
                    value={keyPassphrase}
                    onChange={(e) => setKeyPassphrase(e.target.value)}
                    placeholder={
                      profile?.has_key_passphrase && profile.auth_type === "key"
                        ? "Passphrase stored in vault"
                        : "Leave empty if key is unencrypted"
                    }
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    className="input-addon-btn"
                    onClick={() => setShowKeyPassphrase((v) => !v)}
                    aria-label={
                      showKeyPassphrase ? "Hide passphrase" : "Show passphrase"
                    }
                  >
                    {showKeyPassphrase ? (
                      <EyeOffIcon size={15} />
                    ) : (
                      <EyeIcon size={15} />
                    )}
                  </button>
                </div>
              </div>
            </>
          )}

          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={bypassIranLAN}
              onChange={(e) => setBypassIranLAN(e.target.checked)}
            />
            <span>Bypass Iran (<code dir="ltr">*.ir</code>) &amp; LAN subnets</span>
          </label>

          {profile?.pinned_host_key && (
            <div className="pinned-key-box">
              <div className="pinned-key-box__top">
                <span className="pinned-key-box__title">
                  <ShieldCheckIcon size={14} />
                  <span>Pinned Host Key ({profile.pinned_host_key.algorithm})</span>
                </span>
                <button
                  type="button"
                  className="btn btn--xs btn--danger-outline"
                  onClick={handleClearHostKey}
                  disabled={clearingKey}
                >
                  {clearingKey ? "Clearing..." : "Clear Host Key"}
                </button>
              </div>
              <code className="pinned-key-box__fp" dir="ltr">
                {profile.pinned_host_key.sha256}
              </code>
            </div>
          )}

          {error && (
            <div className="inline-alert inline-alert--error" role="alert">
              {error}
            </div>
          )}

          <div className="modal-footer modal-footer--between">
            <div>
              {isEdit && (
                <div className="delete-group">
                  <button
                    type="button"
                    className={`btn btn--sm ${confirmDelete ? "btn--danger" : "btn--danger-outline"}`}
                    onClick={handleDelete}
                    disabled={deleting || saving}
                  >
                    <TrashIcon size={13} />
                    <span>
                      {deleting
                        ? "Deleting..."
                        : confirmDelete
                          ? "Confirm Delete?"
                          : "Delete"}
                    </span>
                  </button>
                  {confirmDelete && !deleting && (
                    <button
                      type="button"
                      className="btn btn--sm btn--ghost"
                      onClick={() => setConfirmDelete(false)}
                    >
                      Cancel
                    </button>
                  )}
                </div>
              )}
            </div>

            <div className="modal-footer__right">
              <button
                type="button"
                className="btn btn--ghost"
                onClick={onClose}
                disabled={saving || deleting}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="btn btn--primary"
                disabled={saving || deleting}
              >
                <LockIcon size={14} />
                <span>{saving ? "Saving..." : isEdit ? "Save Changes" : "Save Profile"}</span>
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}
