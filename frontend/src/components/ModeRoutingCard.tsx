import { useEffect, useState } from "react";
import type { ProfileView, ProxyCapabilitiesDTO } from "../api/bridge";
import { copyToClipboard } from "../utils/format";
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CopyIcon,
  ShieldCheckIcon,
  TerminalIcon,
} from "./Icons";

interface ModeRoutingCardProps {
  mode: "proxy" | "tun";
  tunEnabled: boolean;
  activeProfile: ProfileView | null;
  proxyCaps: ProxyCapabilitiesDTO;
  envSnippet: string;
  bypassBusy: boolean;
  onModeChange: (mode: "proxy" | "tun") => void;
  onToggleBypass: (bypass: boolean) => void;
}

export function ModeRoutingCard({
  mode,
  tunEnabled,
  activeProfile,
  proxyCaps,
  envSnippet,
  bypassBusy,
  onModeChange,
  onToggleBypass,
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

  return (
    <section className="card routing-card" aria-label="Mode and routing controls">
      <div className="segmented" role="radiogroup" aria-label="Tunnel mode">
        <button
          type="button"
          role="radio"
          aria-checked={mode === "proxy"}
          className={`segmented__btn ${mode === "proxy" ? "is-active" : ""}`}
          onClick={() => onModeChange("proxy")}
        >
          <span>System Proxy (No Admin)</span>
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={mode === "tun"}
          aria-disabled={!tunEnabled}
          disabled={!tunEnabled}
          className={`segmented__btn ${mode === "tun" ? "is-active" : ""} ${!tunEnabled ? "is-m2-locked" : ""}`}
          onClick={() => {
            if (tunEnabled) {
              onModeChange("tun");
            }
          }}
          title={
            tunEnabled
              ? "Route all OS traffic through TUN (requires elevation)"
              : "Available in Milestone 2 (Full TUN + DNS mode)"
          }
        >
          <span className="segmented__tun-label">
            <ShieldCheckIcon size={13} />
            <span>Full TUN (All Apps)</span>
          </span>
          {!tunEnabled && <span className="m2-pill">Milestone 2</span>}
        </button>
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

      {mode === "proxy" && (
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
      )}
    </section>
  );
}
