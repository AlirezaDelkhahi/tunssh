import type { StartupRecoveryDTO } from "../api/bridge";
import { AlertTriangleIcon, CloseIcon, RotateCcwIcon, ShieldCheckIcon } from "./Icons";

interface RecoveryBannerProps {
  recovery: StartupRecoveryDTO;
  restoring: boolean;
  onRestoreNetwork: () => void;
  onDismiss: () => void;
}

export function RecoveryBanner({
  recovery,
  restoring,
  onRestoreNetwork,
  onDismiss,
}: RecoveryBannerProps) {
  if (!recovery.recovered && !recovery.needs_elevation) {
    return null;
  }

  const isElevationNeeded = Boolean(recovery.needs_elevation);
  const fallbackMessage = isElevationNeeded
    ? "Previous TUN session ended unexpectedly. Restore OS routes and DNS to repair connectivity."
    : `Unclean shutdown detected (${recovery.mode || "proxy"} mode). OS network settings were automatically restored.`;

  return (
    <section
      className={`recovery-banner ${isElevationNeeded ? "recovery-banner--warn" : "recovery-banner--ok"}`}
      role={isElevationNeeded ? "alert" : "status"}
      aria-live={isElevationNeeded ? "assertive" : "polite"}
    >
      <div className="recovery-banner__icon">
        {isElevationNeeded ? (
          <AlertTriangleIcon size={16} />
        ) : (
          <ShieldCheckIcon size={16} />
        )}
      </div>
      <div className="recovery-banner__body">
        <div className="recovery-banner__title">
          {isElevationNeeded ? "Network Recovery Required" : "Startup Recovery Complete"}
        </div>
        <p className="recovery-banner__msg">
          {recovery.message || fallbackMessage}
        </p>
        {isElevationNeeded && (
          <div className="recovery-banner__actions">
            <button
              type="button"
              className="btn btn--sm btn--warn-restore"
              onClick={onRestoreNetwork}
              disabled={restoring}
            >
              <RotateCcwIcon size={13} />
              <span>{restoring ? "Restoring..." : "Restore Network"}</span>
            </button>
          </div>
        )}
      </div>
      <button
        type="button"
        className="icon-btn icon-btn--ghost"
        onClick={onDismiss}
        disabled={restoring}
        aria-label="Dismiss recovery notification"
        title="Dismiss"
      >
        <CloseIcon size={14} />
      </button>
    </section>
  );
}
