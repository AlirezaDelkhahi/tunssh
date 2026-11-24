import { RotateCcwIcon, TerminalIcon } from "./Icons";

interface FooterBarProps {
  logsOpen: boolean;
  unreadSeverity: "none" | "warn" | "error";
  unreadCount: number;
  restoringNetwork: boolean;
  tunEnabled?: boolean;
  onToggleLogs: () => void;
  onRestoreNetwork: () => void;
}

export function FooterBar({
  logsOpen,
  unreadSeverity,
  unreadCount,
  restoringNetwork,
  tunEnabled = false,
  onToggleLogs,
  onRestoreNetwork,
}: FooterBarProps) {
  return (
    <footer className="footer-bar">
      <button
        type="button"
        className={`btn btn--surface footer-bar__logs-btn ${logsOpen ? "is-open" : ""}`}
        onClick={onToggleLogs}
        aria-expanded={logsOpen}
        aria-controls="diagnostic-log-drawer"
      >
        <TerminalIcon size={14} />
        <span>Diagnostic Logs</span>
        {unreadSeverity !== "none" && (
          <span
            className={`unread-dot unread-dot--${unreadSeverity}`}
            title={`${unreadCount} unread warning/error log${unreadCount === 1 ? "" : "s"}`}
            aria-label={`${unreadCount} unread warnings or errors`}
          />
        )}
      </button>

      <button
        type="button"
        className="btn btn--panic"
        onClick={onRestoreNetwork}
        disabled={restoringNetwork}
        title={
          tunEnabled
            ? "Idempotently restore OS routes, DNS, and system proxy settings"
            : "Idempotently restore OS system proxy settings"
        }
      >
        <RotateCcwIcon size={14} />
        <span>{restoringNetwork ? "Restoring..." : "Restore Network"}</span>
      </button>
    </footer>
  );
}
