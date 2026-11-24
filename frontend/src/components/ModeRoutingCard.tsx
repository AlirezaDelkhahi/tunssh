import { useEffect, useState } from "react";
import type {
  ProfileView,
  ProxyCapabilitiesDTO,
  TUNCapsDTO,
} from "../api/bridge";
import { copyToClipboard } from "../utils/format";
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CopyIcon,
  LockIcon,
  ShieldCheckIcon,
  ShieldIcon,
  TerminalIcon,
} from "./Icons";

interface ModeRoutingCardProps {
  mode: "proxy" | "tun";
  tunEnabled: boolean;
  tunCaps: TUNCapsDTO;
  isTunnelActive: boolean;
  activeProfile: ProfileView | null;
  proxyCaps: ProxyCapabilitiesDTO;
  envSnippet: string;
  bypassBusy: boolean;
  persistentCapBusy: boolean;
  onModeChange: (mode: "proxy" | "tun") => void;
  onToggleBypass: (bypass: boolean) => void;
  onEnablePersistentTUNAccess: () => void;
}

export function ModeRoutingCard({
  mode,
  tunEnabled,
  tunCaps,
  isTunnelActive,
  activeProfile,
  proxyCaps,
  envSnippet,
  bypassBusy,
  persistentCapBusy,
  onModeChange,
  onToggleBypass,
  onEnablePersistentTUNAccess,
}: ModeRoutingCardProps) {
  const [envExpanded, setEnvExpanded] = useState(!proxyCaps.auto_supported);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!proxyCaps.auto_supported) {
      setEnvExpanded(true);
    }
  }, [proxyCaps.auto_supported]);

  useEffect(() => {
    if (!copied) {
      return undefined;
    }
    const timer = window.setTimeout(() => setCopied(false), 1800);
    return () => window.clearTimeout(timer);
  }, [copied]);

  const handleCopyEnv = async () => {
    const ok = await copyToClipboard(envSnippet);
    if (ok) {
      setCopied(true);
    }
  };

  const bypassChecked = activeProfile?.bypass_iran_lan ?? true;
  const tunIface = tunCaps.iface_name || "tunssh0";
  const tunIPv4 = tunCaps.tun_ipv4 || "198.18.0.1";
  const tunDNS = tunCaps.tun_dns || "198.18.0.2";

  const tunTitle = isTunnelActive
    ? "Disconnect before switching tunnel mode"
    : !tunEnabled
      ? "Available in Milestone 2 (Full TUN + DNS mode)"
      : tunCaps.requires_elevation
        ? tunCaps.has_persistent_cap
          ? "Route all OS traffic through TUN (persistent capability applies on next launch)"
          : "Route all OS traffic through TUN (requires Admin / pkexec elevation)"
        : "Route all OS traffic through TUN directly (no elevation needed)";

  return (
    <section className="card routing-card" aria-label="Mode and routing controls">
      <div className="segmented-wrap">
        <div
          className={`segmented ${isTunnelActive ? "is-locked" : ""}`}
          role="radiogroup"
          aria-label="Tunnel mode"
          title={
            isTunnelActive
              ? "Disconnect before switching tunnel mode"
              : undefined
          }
        >
          <button
            type="button"
            role="radio"
            aria-checked={mode === "proxy"}
            aria-disabled={isTunnelActive}
            disabled={isTunnelActive}
            className={`segmented__btn ${mode === "proxy" ? "is-active" : ""}`}
            onClick={() => {
              if (!isTunnelActive) {
                onModeChange("proxy");
              }
            }}
            title={
              isTunnelActive
                ? "Disconnect before switching tunnel mode"
                : "Use local SOCKS5/HTTP system proxy without admin privileges"
            }
          >
            <span>System Proxy (No Admin)</span>
          </button>
          <button
            type="button"
            role="radio"
            aria-checked={mode === "tun"}
            aria-disabled={isTunnelActive || !tunEnabled}
            disabled={isTunnelActive || !tunEnabled}
            className={`segmented__btn ${mode === "tun" ? "is-active" : ""} ${!tunEnabled ? "is-m2-locked" : ""}`}
            onClick={() => {
              if (tunEnabled && !isTunnelActive) {
                onModeChange("tun");
              }
            }}
            title={tunTitle}
          >
            <span className="segmented__tun-label">
              {!tunEnabled && <ShieldCheckIcon size={13} />}
              <span>Full TUN (All Apps)</span>
            </span>
            {!tunEnabled ? (
              <span className="m2-pill">Milestone 2</span>
            ) : tunCaps.requires_elevation ? (
              <span
                className="tun-cap-badge tun-cap-badge--elevated"
                title={
                  tunCaps.has_persistent_cap
                    ? "Elevation still required until app restart"
                    : "Admin / pkexec elevation required"
                }
              >
                <ShieldIcon size={10} />
                <span>Admin</span>
              </span>
            ) : (
              <span
                className="tun-cap-badge tun-cap-badge--direct"
                title="Direct TUN access active (no elevation prompt)"
              >
                <CheckIcon size={10} />
                <span>Direct</span>
              </span>
            )}
          </button>
        </div>

        {isTunnelActive && (
          <p className="mode-locked-hint" role="note">
            <LockIcon size={11} />
            <span>Disconnect before switching tunnel mode</span>
          </p>
        )}
      </div>

      <div className="routing-row">
        <div className="routing-row__info">
          <span id="bypass-iran-label" className="routing-row__title">
            Bypass Iran (.ir) &amp; LAN
          </span>
          <span className="routing-row__desc">
            Direct route for <code dir="ltr">*.ir</code> and local{" "}
            <code dir="ltr">RFC1918</code> subnets
          </span>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={bypassChecked}
          aria-labelledby="bypass-iran-label"
          className={`switch ${bypassChecked ? "is-checked" : ""}`}
          disabled={!activeProfile || bypassBusy}
          onClick={() => onToggleBypass(!bypassChecked)}
        >
          <span className="switch__thumb" />
        </button>
      </div>

      {mode === "proxy" ? (
        <div className="env-bar">
          <div className="env-bar__header">
            <button
              type="button"
              className="env-bar__toggle"
              onClick={() => setEnvExpanded((v) => !v)}
              aria-expanded={envExpanded}
              aria-controls="cli-env-snippet-panel"
            >
              <TerminalIcon size={13} />
              <span>CLI / Tiling WM Env</span>
              {!proxyCaps.auto_supported && (
                <span className="env-tag" title={`Detected environment: ${proxyCaps.desktop_env}`}>
                  manual-env
                </span>
              )}
              {envExpanded ? (
                <ChevronUpIcon size={13} />
              ) : (
                <ChevronDownIcon size={13} />
              )}
            </button>

            <button
              type="button"
              className={`copy-pill ${copied ? "is-copied" : ""}`}
              onClick={handleCopyEnv}
              aria-label="Copy shell proxy environment variables"
            >
              {copied ? <CheckIcon size={12} /> : <CopyIcon size={12} />}
              <span>{copied ? "Copied" : "Copy"}</span>
            </button>
          </div>

          {envExpanded && (
            <div id="cli-env-snippet-panel" className="env-bar__body">
              {!proxyCaps.auto_supported && (
                <p className="env-bar__note">
                  Desktop auto-proxy unavailable ({proxyCaps.desktop_env || "manual-env"}). Export
                  in your shell or app launcher:
                </p>
              )}
              <pre className="env-bar__code" dir="ltr">
                <code>{envSnippet}</code>
              </pre>
            </div>
          )}
        </div>
      ) : (
        <div className="tun-bar" role="region" aria-label="Full TUN adapter settings">
          <div className="tun-bar__header">
            <span className="tun-bar__summary">
              <ShieldCheckIcon size={13} className="tun-bar__icon" />
              <code className="tun-bar__spec" dir="ltr">
                {tunIface} • {tunIPv4}/15 • DNS {tunDNS}
              </code>
            </span>
            {tunCaps.has_persistent_cap && (
              <span
                className="tun-cap-badge tun-cap-badge--direct"
                title={
                  tunCaps.requires_elevation
                    ? "Persistent capability enabled — takes effect on next launch"
                    : "Persistent TUN capability active"
                }
              >
                <CheckIcon size={10} />
                <span>Persistent</span>
              </span>
            )}
          </div>

          <p className="tun-bar__note">
            Encrypted DNS-over-TCP (<code dir="ltr">:53</code>) &amp; IPv6 leak protection
            {tunCaps.supported === false
              ? " — TUN device unavailable on this host."
              : "."}
          </p>

          {tunCaps.has_persistent_cap && tunCaps.requires_elevation && (
            <p className="tun-bar__subnote">
              Persistent TUN access is configured and takes effect on next launch.
            </p>
          )}

          {tunCaps.can_enable_persistent_cap && !tunCaps.has_persistent_cap && (
            <button
              type="button"
              className="btn btn--xs btn--surface tun-bar__action"
              onClick={onEnablePersistentTUNAccess}
              disabled={persistentCapBusy}
              title="Grant one-time CAP_NET_ADMIN access via pkexec so Full TUN works without future prompts"
            >
              <ShieldIcon size={12} />
              <span>
                {persistentCapBusy
                  ? "Enabling Persistent Access..."
                  : "Enable One-Time Persistent TUN Access"}
              </span>
            </button>
          )}
        </div>
      )}
    </section>
  );
}
