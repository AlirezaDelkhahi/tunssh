import { useEffect, useState } from "react";
import type { ProfileView, TUNCapsDTO, TunnelStatusDTO } from "../api/bridge";
import { formatBytes, formatDuration, formatRate } from "../utils/format";
import {
  ActivityIcon,
  AlertTriangleIcon,
  ArrowDownIcon,
  ArrowUpIcon,
  EditIcon,
  PowerIcon,
} from "./Icons";

interface HeroConnectionCardProps {
  status: TunnelStatusDTO;
  tunCaps: TUNCapsDTO;
  activeProfile: ProfileView | null;
  busy: boolean;
  onConnect: () => void;
  onDisconnect: () => void;
  onEditProfile: () => void;
  onCreateProfile: () => void;
}

const PROFILE_FIXABLE_ERROR_CODES = new Set([
  "ERR_PORT22_TIMEOUT",
  "ERR_DPI_RESET",
  "ERR_CONN_REFUSED",
  "ERR_AUTH_FAILED",
  "ERR_KEY_INVALID",
]);

export function HeroConnectionCard({
  status,
  tunCaps,
  activeProfile,
  busy,
  onConnect,
  onDisconnect,
  onEditProfile,
  onCreateProfile,
}: HeroConnectionCardProps) {
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  useEffect(() => {
    if (status.state !== "connected" || !status.connected_at_unix) {
      setElapsedSeconds(0);
      return undefined;
    }

    const updateElapsed = () => {
      const nowSec = Math.floor(Date.now() / 1000);
      setElapsedSeconds(Math.max(0, nowSec - status.connected_at_unix));
    };

    updateElapsed();
    const timer = window.setInterval(updateElapsed, 1000);
    return () => window.clearInterval(timer);
  }, [status.state, status.connected_at_unix]);

  const isConnected = status.state === "connected";
  const isTransitioning =
    status.state === "connecting" || status.state === "reconnecting";
  const isError = status.state === "error";

  const statusMeta = (() => {
    switch (status.state) {
      case "connected":
        return { label: "Connected", tone: "connected", pulse: false };
      case "connecting":
        return { label: "Connecting...", tone: "connecting", pulse: true };
      case "reconnecting":
        return {
          label: `Reconnecting (attempt #${Math.max(1, status.attempt)})...`,
          tone: "connecting",
          pulse: true,
        };
      case "error":
        return { label: "Action Required", tone: "error", pulse: false };
      case "disconnected":
      default:
        return { label: "Disconnected", tone: "disconnected", pulse: false };
    }
  })();

  const handlePrimaryClick = () => {
    if (!activeProfile) {
      onCreateProfile();
      return;
    }
    if (isConnected || isTransitioning) {
      onDisconnect();
      return;
    }
    onConnect();
  };

  const buttonLabel = (() => {
    if (!activeProfile) {
      return "Create First Profile";
    }
    if (status.state === "connecting") {
      return "Cancel Connection";
    }
    if (status.state === "reconnecting") {
      return "Cancel Reconnect";
    }
    if (isConnected) {
      return "Disconnect";
    }
    return "Connect";
  })();

  const buttonClass = (() => {
    if (!activeProfile) {
      return "connect-btn connect-btn--primary";
    }
    if (isConnected) {
      return "connect-btn connect-btn--disconnect";
    }
    if (isTransitioning) {
      return "connect-btn connect-btn--cancel";
    }
    return "connect-btn connect-btn--primary";
  })();

  const showProfileQuickFix = Boolean(
    activeProfile &&
      status.last_error &&
      PROFILE_FIXABLE_ERROR_CODES.has(status.last_error.code),
  );

  return (
    <section className="card hero-card" aria-label="Tunnel connection">
      <div className="hero-card__top">
        <div
          className={`status-pill status-pill--${statusMeta.tone}`}
          role="status"
          aria-live="polite"
        >
          <span
            className={`status-dot ${statusMeta.pulse ? "status-dot--pulse" : ""}`}
            aria-hidden="true"
          />
          <span className="status-pill__label">{statusMeta.label}</span>
        </div>

        <div className="hero-card__meta">
          {isConnected &&
            (status.mode === "tun" ? (
              <code
                className="endpoint-chip endpoint-chip--tun"
                dir="ltr"
                title={`Full TUN adapter (${tunCaps.iface_name || "tunssh0"}) with DNS ${tunCaps.tun_dns || "198.18.0.2"}:53`}
              >
                {tunCaps.iface_name || "tunssh0"} • {tunCaps.tun_dns || "198.18.0.2"}:53
              </code>
            ) : (
              <code
                className="endpoint-chip"
                dir="ltr"
                title="Local SOCKS5 / HTTP ports"
              >
                :{status.socks_port || 10808} / :{status.http_port || 10809}
              </code>
            ))}
          <span
            className={`session-timer ${isConnected ? "is-active" : ""}`}
            dir="ltr"
            aria-label="Session duration"
          >
            {formatDuration(elapsedSeconds)}
          </span>
        </div>
      </div>

      <button
        type="button"
        className={buttonClass}
        onClick={handlePrimaryClick}
        disabled={busy}
        aria-keyshortcuts="Control+Enter"
      >
        <span className="connect-btn__inner">
          <PowerIcon size={17} />
          <span>{buttonLabel}</span>
        </span>
        {activeProfile && (
          <kbd className="kbd-hint" aria-hidden="true">
            Ctrl+↵
          </kbd>
        )}
      </button>

      {status.last_error && (
        <div
          className={`error-callout ${isError ? "is-critical" : ""}`}
          role="alert"
        >
          <div className="error-callout__header">
            <span className="error-callout__title">
              <AlertTriangleIcon size={14} />
              <code className="error-code" dir="ltr">
                {status.last_error.code}
              </code>
            </span>
            {showProfileQuickFix && (
              <button
                type="button"
                className="link-btn"
                onClick={onEditProfile}
              >
                <EditIcon size={12} />
                <span>Edit Profile</span>
              </button>
            )}
          </div>
          <p className="error-callout__message">{status.last_error.message}</p>
          {status.last_error.action_hint && (
            <p className="error-callout__hint">
              {status.last_error.action_hint}
            </p>
          )}
        </div>
      )}

      <div className="telemetry-grid" aria-label="Live telemetry">
        <div className="telemetry-cell">
          <span className="telemetry-cell__label">
            <ActivityIcon size={12} />
            <span>Latency</span>
          </span>
          <span className="telemetry-cell__value" dir="ltr">
            {isConnected && status.rtt_ms > 0 ? `${status.rtt_ms} ms` : "--"}
          </span>
          <span className="telemetry-cell__sub">
            {isConnected ? "SSH keepalive" : "Idle"}
          </span>
        </div>

        <div className="telemetry-cell">
          <span className="telemetry-cell__label">
            <ArrowDownIcon size={12} />
            <span>Down</span>
          </span>
          <span className="telemetry-cell__value" dir="ltr">
            {isConnected ? formatRate(status.rx_rate_bps) : "0 KB/s"}
          </span>
          <span className="telemetry-cell__sub" dir="ltr">
            Total {formatBytes(status.rx_bytes)}
          </span>
        </div>

        <div className="telemetry-cell">
          <span className="telemetry-cell__label">
            <ArrowUpIcon size={12} />
            <span>Up</span>
          </span>
          <span className="telemetry-cell__value" dir="ltr">
            {isConnected ? formatRate(status.tx_rate_bps) : "0 KB/s"}
          </span>
          <span className="telemetry-cell__sub" dir="ltr">
            Total {formatBytes(status.tx_bytes)}
          </span>
        </div>
      </div>
    </section>
  );
}
