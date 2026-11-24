import { useEffect, useMemo, useRef, useState } from "react";
import type { LogEntryDTO } from "../api/bridge";
import { copyToClipboard, formatLogTime } from "../utils/format";
import { CheckIcon, CloseIcon, CopyIcon, TrashIcon } from "./Icons";

interface LogDrawerProps {
  open: boolean;
  entries: LogEntryDTO[];
  onClose: () => void;
  onClear: () => Promise<void>;
  onExportRedacted: () => Promise<string>;
}

export function LogDrawer({
  open,
  entries,
  onClose,
  onClear,
  onExportRedacted,
}: LogDrawerProps) {
  const [filterMode, setFilterMode] = useState<"all" | "alerts">("all");
  const [copied, setCopied] = useState(false);
  const [clearing, setClearing] = useState(false);
  const streamRef = useRef<HTMLDivElement>(null);

  const visibleEntries = useMemo(() => {
    const capped = entries.slice(-500);
    if (filterMode === "alerts") {
      return capped.filter((e) => e.level === "WARN" || e.level === "ERROR");
    }
    return capped;
  }, [entries, filterMode]);

  useEffect(() => {
    if (!open || !streamRef.current) {
      return;
    }
    streamRef.current.scrollTop = streamRef.current.scrollHeight;
  }, [open, visibleEntries.length]);

  useEffect(() => {
    if (!copied) {
      return undefined;
    }
    const timer = window.setTimeout(() => setCopied(false), 1800);
    return () => window.clearTimeout(timer);
  }, [copied]);

  if (!open) {
    return null;
  }

  const handleCopy = async () => {
    const text = await onExportRedacted();
    if (await copyToClipboard(text)) {
      setCopied(true);
    }
  };

  const handleClear = async () => {
    setClearing(true);
    try {
      await onClear();
    } finally {
      setClearing(false);
    }
  };

  return (
    <section
      id="diagnostic-log-drawer"
      className="log-drawer"
      aria-label="Diagnostic Logs"
    >
      <div className="log-drawer__header">
        <div className="log-drawer__title-group">
          <h2 className="log-drawer__title">Diagnostic Logs</h2>
          <span className="log-drawer__count" dir="ltr">
            {visibleEntries.length} / 500
          </span>
          <div className="log-filter" role="group" aria-label="Filter log level">
            <button
              type="button"
              className={`log-filter__btn ${filterMode === "all" ? "is-active" : ""}`}
              onClick={() => setFilterMode("all")}
            >
              All
            </button>
            <button
              type="button"
              className={`log-filter__btn ${filterMode === "alerts" ? "is-active" : ""}`}
              onClick={() => setFilterMode("alerts")}
            >
              Warn/Err
            </button>
          </div>
        </div>

        <div className="log-drawer__actions">
          <button
            type="button"
            className={`btn btn--xs btn--surface ${copied ? "is-copied" : ""}`}
            onClick={handleCopy}
            disabled={entries.length === 0}
          >
            {copied ? <CheckIcon size={12} /> : <CopyIcon size={12} />}
            <span>{copied ? "Copied" : "Copy Redacted Logs"}</span>
          </button>
          <button
            type="button"
            className="btn btn--xs btn--ghost"
            onClick={handleClear}
            disabled={clearing || entries.length === 0}
            title="Clear log buffer"
          >
            <TrashIcon size={12} />
            <span>Clear</span>
          </button>
          <button
            type="button"
            className="icon-btn icon-btn--ghost"
            onClick={onClose}
            aria-label="Close diagnostic logs"
          >
            <CloseIcon size={14} />
          </button>
        </div>
      </div>

      <div ref={streamRef} className="log-drawer__stream" dir="ltr">
        {visibleEntries.length === 0 ? (
          <div className="log-empty">
            {filterMode === "alerts"
              ? "No warnings or errors recorded."
              : "No diagnostic log entries yet."}
          </div>
        ) : (
          visibleEntries.map((entry, idx) => (
            <div
              key={`${entry.timestamp}-${idx}`}
              className={`log-line log-line--${entry.level.toLowerCase()}`}
            >
              <div className="log-line__main">
                <span className="log-line__time">
                  {formatLogTime(entry.timestamp)}
                </span>
                <span className={`log-level log-level--${entry.level.toLowerCase()}`}>
                  {entry.level}
                </span>
                {entry.code && <code className="log-code">{entry.code}</code>}
                <span className="log-line__msg">{entry.message}</span>
              </div>
              {entry.action_hint && (
                <div className="log-line__hint">
                  <strong>Hint:</strong> {entry.action_hint}
                </div>
              )}
            </div>
          ))
        )}
      </div>
    </section>
  );
}
