import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  formatBridgeError,
  isWailsRuntime,
  subscribeEvent,
  type HostKeyPromptDTO,
  type LogEntryDTO,
  type ProfileView,
  type ProxyCapabilitiesDTO,
  type SaveProfileRequest,
  type StartupRecoveryDTO,
  type TunnelStatusDTO,
} from "./api/bridge";
import { FooterBar } from "./components/FooterBar";
import { HeaderBar } from "./components/HeaderBar";
import { HeroConnectionCard } from "./components/HeroConnectionCard";
import { HostKeyModal } from "./components/HostKeyModal";
import { LogDrawer } from "./components/LogDrawer";
import { ModeRoutingCard } from "./components/ModeRoutingCard";
import { ProfileModal } from "./components/ProfileModal";
import { RecoveryBanner } from "./components/RecoveryBanner";
import { ShareModal } from "./components/ShareModal";
import { VaultUnlockModal } from "./components/VaultUnlockModal";

const DEFAULT_STATUS: TunnelStatusDTO = {
  state: "disconnected",
  profile_id: "",
  mode: "proxy",
  attempt: 0,
  rtt_ms: 0,
  rx_bytes: 0,
  tx_bytes: 0,
  rx_rate_bps: 0,
  tx_rate_bps: 0,
  connected_at_unix: 0,
  socks_port: 10808,
  http_port: 10809,
  env_snippet:
    "export ALL_PROXY=socks5h://127.0.0.1:10808 HTTP_PROXY=http://127.0.0.1:10809 HTTPS_PROXY=http://127.0.0.1:10809",
  last_error: null,
};

const DEFAULT_PROXY_CAPS: ProxyCapabilitiesDTO = {
  auto_supported: true,
  desktop_env: "",
};

interface ToastState {
  tone: "info" | "success" | "error";
  message: string;
}

export function App() {
  const [loading, setLoading] = useState(true);
  const [bootError, setBootError] = useState<string | null>(null);

  const [vaultBackend, setVaultBackend] = useState<"keyring" | "encrypted-file">(
    "keyring",
  );
  const [vaultLocked, setVaultLocked] = useState(false);
  const [tunEnabled, setTunEnabled] = useState(false);
  const [proxyCaps, setProxyCaps] =
    useState<ProxyCapabilitiesDTO>(DEFAULT_PROXY_CAPS);
  const [status, setStatus] = useState<TunnelStatusDTO>(DEFAULT_STATUS);
  const [envSnippetFallback, setEnvSnippetFallback] = useState(
    DEFAULT_STATUS.env_snippet,
  );
  const [profiles, setProfiles] = useState<ProfileView[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState("");
  const [activeMode, setActiveMode] = useState<"proxy" | "tun">("proxy");

  const [recovery, setRecovery] = useState<StartupRecoveryDTO | null>(null);
  const [recoveryDismissed, setRecoveryDismissed] = useState(false);

  const [hostKeyPrompt, setHostKeyPrompt] = useState<HostKeyPromptDTO | null>(
    null,
  );
  const [hostKeyBusy, setHostKeyBusy] = useState(false);

  const [profileModal, setProfileModal] = useState<{
    open: boolean;
    profileId: string | null;
  }>({ open: false, profileId: null });
  const [shareModalOpen, setShareModalOpen] = useState(false);

  const [logsOpen, setLogsOpen] = useState(false);
  const [logs, setLogs] = useState<LogEntryDTO[]>([]);
  const [unreadSeverity, setUnreadSeverity] = useState<
    "none" | "warn" | "error"
  >("none");
  const [unreadCount, setUnreadCount] = useState(0);

  const [connectBusy, setConnectBusy] = useState(false);
  const [disconnectBusy, setDisconnectBusy] = useState(false);
  const [bypassBusy, setBypassBusy] = useState(false);
  const [restoringNetwork, setRestoringNetwork] = useState(false);
  const [toast, setToast] = useState<ToastState | null>(null);

  const showToast = useCallback(
    (tone: ToastState["tone"], message: string) => {
      setToast({ tone, message });
    },
    [],
  );

  useEffect(() => {
    if (!toast) {
      return undefined;
    }
    const timer = window.setTimeout(() => setToast(null), 3500);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const loadBootstrap = useCallback(async () => {
    setLoading(true);
    setBootError(null);
    try {
      const [boot, initialLogs] = await Promise.all([
        api.GetBootstrapState(),
        api.GetLogs().catch(() => [] as LogEntryDTO[]),
      ]);

      setVaultBackend(boot.vault_backend);
      setVaultLocked(boot.vault_locked);
      setTunEnabled(boot.tun_enabled);
      setProxyCaps(boot.proxy_caps);
      setStatus(boot.status);
      setProfiles(boot.profiles);
      setRecovery(boot.recovery ?? null);
      setRecoveryDismissed(false);
      setLogs(initialLogs.slice(-500));

      const preferredId =
        boot.status.profile_id &&
        boot.profiles.some((p) => p.id === boot.status.profile_id)
          ? boot.status.profile_id
          : boot.profiles[0]?.id ?? "";
      setSelectedProfileId(preferredId);
      setActiveMode(boot.tun_enabled && boot.status.mode === "tun" ? "tun" : "proxy");

      if (!boot.status.env_snippet) {
        api
          .GetEnvSnippet()
          .then((snippet) => {
            if (snippet) {
              setEnvSnippetFallback(snippet);
            }
          })
          .catch(() => undefined);
      }
    } catch (err) {
      setBootError(formatBridgeError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadBootstrap();
  }, [loadBootstrap]);

  useEffect(() => {
    const unsubStatus = subscribeEvent("tunnel:status", (next) => {
      setStatus(next);
      if (next.profile_id) {
        setSelectedProfileId((prev) =>
          next.state === "connecting" ||
          next.state === "connected" ||
          next.state === "reconnecting"
            ? next.profile_id
            : prev || next.profile_id,
        );
      }
      if (next.state === "connected") {
        api
          .ListProfiles()
          .then((list) => setProfiles(list))
          .catch(() => undefined);
      }
    });

    const unsubStats = subscribeEvent("tunnel:stats", (next) => {
      setStatus((prev) => (prev.state === "connected" ? next : prev));
    });

    const unsubHostKey = subscribeEvent("tunnel:hostkey_prompt", (prompt) => {
      setHostKeyPrompt(prompt);
    });

    const unsubRecovery = subscribeEvent("tunnel:recovery", (rec) => {
      setRecovery(rec);
      setRecoveryDismissed(false);
    });

    return () => {
      unsubStatus();
      unsubStats();
      unsubHostKey();
      unsubRecovery();
    };
  }, []);

  useEffect(() => {
    const unsubLog = subscribeEvent("tunnel:log", (entry) => {
      setLogs((prev) => [...prev.slice(-499), entry]);
      if (!logsOpen && (entry.level === "WARN" || entry.level === "ERROR")) {
        setUnreadCount((count) => count + 1);
        setUnreadSeverity((prev) => {
          if (entry.level === "ERROR" || prev === "error") {
            return "error";
          }
          return "warn";
        });
      }
    });
    return () => unsubLog();
  }, [logsOpen]);

  const activeProfile = useMemo(() => {
    if (!selectedProfileId) {
      return profiles[0] ?? null;
    }
    return (
      profiles.find((p) => p.id === selectedProfileId) ?? profiles[0] ?? null
    );
  }, [profiles, selectedProfileId]);

  const editingProfile = useMemo(() => {
    if (!profileModal.profileId) {
      return null;
    }
    return profiles.find((p) => p.id === profileModal.profileId) ?? null;
  }, [profiles, profileModal.profileId]);

  const isTunnelActive =
    status.state === "connected" ||
    status.state === "connecting" ||
    status.state === "reconnecting";

  const hasOpenModal =
    vaultLocked ||
    Boolean(hostKeyPrompt) ||
    profileModal.open ||
    shareModalOpen;

  const handleConnect = useCallback(async () => {
    if (!activeProfile) {
      setProfileModal({ open: true, profileId: null });
      return;
    }
    setConnectBusy(true);
    try {
      await api.Connect(activeProfile.id, activeMode);
    } catch (err) {
      const msg = formatBridgeError(err);
      if (!/context canceled/i.test(msg)) {
        showToast("error", msg);
      }
    } finally {
      setConnectBusy(false);
    }
  }, [activeProfile, activeMode, showToast]);

  const handleDisconnect = useCallback(async () => {
    setDisconnectBusy(true);
    try {
      await api.Disconnect();
    } catch (err) {
      showToast("error", formatBridgeError(err));
    } finally {
      setDisconnectBusy(false);
    }
  }, [showToast]);

  useEffect(() => {
    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      if (hasOpenModal) {
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        if (isTunnelActive) {
          if (!disconnectBusy) {
            void handleDisconnect();
          }
        } else if (activeProfile && !connectBusy) {
          void handleConnect();
        }
      } else if (e.key === "Escape" && logsOpen) {
        setLogsOpen(false);
      }
    };

    document.addEventListener("keydown", handleGlobalKeyDown);
    return () => document.removeEventListener("keydown", handleGlobalKeyDown);
  }, [
    hasOpenModal,
    connectBusy,
    disconnectBusy,
    isTunnelActive,
    activeProfile,
    logsOpen,
    handleConnect,
    handleDisconnect,
  ]);

  const handleUnlockVault = async (passphrase: string) => {
    try {
      await api.UnlockVault(passphrase);
      await loadBootstrap();
      showToast("success", "Local credential vault unlocked.");
    } catch (err) {
      throw new Error(formatBridgeError(err));
    }
  };

  const handleSaveProfile = async (req: SaveProfileRequest) => {
    const saved = await api.SaveProfile(req);
    setProfiles((prev) => {
      const exists = prev.some((p) => p.id === saved.id);
      if (exists) {
        return prev.map((p) => (p.id === saved.id ? saved : p));
      }
      return [...prev, saved];
    });
    setSelectedProfileId(saved.id);
    showToast(
      "success",
      req.id ? `Updated "${saved.name}".` : `Created "${saved.name}".`,
    );
  };

  const handleDeleteProfile = async (profileID: string) => {
    await api.DeleteProfile(profileID);
    const updated = await api.ListProfiles();
    setProfiles(updated);
    setSelectedProfileId((prev) =>
      prev === profileID ? updated[0]?.id ?? "" : prev,
    );
    showToast("info", "Profile deleted.");
  };

  const handleClearHostKey = async (profileID: string) => {
    const updated = await api.ClearHostKey(profileID);
    setProfiles((prev) =>
      prev.map((p) => (p.id === updated.id ? updated : p)),
    );
    showToast("info", "Pinned host key cleared.");
    return updated;
  };

  const handleToggleBypass = async (bypass: boolean) => {
    if (!activeProfile) {
      return;
    }
    setBypassBusy(true);
    try {
      const updated = await api.SetBypassIranLAN(activeProfile.id, bypass);
      setProfiles((prev) =>
        prev.map((p) => (p.id === updated.id ? updated : p)),
      );
    } catch (err) {
      showToast("error", formatBridgeError(err));
    } finally {
      setBypassBusy(false);
    }
  };

  const handleRestoreNetwork = async () => {
    setRestoringNetwork(true);
    try {
      await api.RestoreNetwork();
      setRecovery((prev) =>
        prev ? { ...prev, needs_elevation: false, recovered: true } : prev,
      );
      showToast("success", "OS network settings verified and restored.");
    } catch (err) {
      showToast("error", formatBridgeError(err));
    } finally {
      setRestoringNetwork(false);
    }
  };

  const handleTrustHostKeyAndConnect = async (prompt: HostKeyPromptDTO) => {
    setHostKeyBusy(true);
    try {
      await api.TrustHostKeyAndConnect(
        prompt.profile_id,
        prompt.algorithm,
        prompt.sha256,
      );
      setHostKeyPrompt(null);
      const list = await api.ListProfiles();
      setProfiles(list);
    } catch (err) {
      showToast("error", formatBridgeError(err));
    } finally {
      setHostKeyBusy(false);
    }
  };

  const handleForgetAndReconnect = async (prompt: HostKeyPromptDTO) => {
    setHostKeyBusy(true);
    try {
      const updated = await api.ForgetHostKey(prompt.profile_id);
      setProfiles((prev) =>
        prev.map((p) => (p.id === updated.id ? updated : p)),
      );
      setHostKeyPrompt(null);
      await api.Connect(prompt.profile_id, activeMode);
    } catch (err) {
      showToast("error", formatBridgeError(err));
    } finally {
      setHostKeyBusy(false);
    }
  };

  const handleCancelHostKey = () => {
    setHostKeyPrompt(null);
    if (isTunnelActive) {
      void api.Disconnect().catch(() => undefined);
    }
  };

  const handleExportShareLink = useCallback(
    (profileID: string, passphrase: string, unsafePlain: boolean) =>
      api.ExportShareLink(profileID, passphrase, unsafePlain),
    [],
  );

  const handleInspectShareLink = useCallback(
    (link: string) => api.InspectShareLink(link),
    [],
  );

  const handleImportProfile = useCallback(
    async (link: string, passphrase: string, allowPlain: boolean) => {
      const imported = await api.ImportShareLink(link, passphrase, allowPlain);
      const list = await api.ListProfiles();
      setProfiles(list);
      setSelectedProfileId(imported.id);
      showToast("success", `Imported profile "${imported.name}".`);
      return imported;
    },
    [showToast],
  );

  const handleToggleLogs = () => {
    setLogsOpen((prev) => {
      const next = !prev;
      if (next) {
        setUnreadCount(0);
        setUnreadSeverity("none");
      }
      return next;
    });
  };

  const handleClearLogs = async () => {
    await api.ClearLogs();
    setLogs([]);
    setUnreadCount(0);
    setUnreadSeverity("none");
  };

  const envSnippet = status.env_snippet || envSnippetFallback;

  if (loading) {
    return (
      <div className="app-shell app-shell--center">
        <div className="boot-card">
          <div className="boot-spinner" aria-hidden="true" />
          <p className="boot-text">Starting tunssh...</p>
        </div>
      </div>
    );
  }

  if (bootError) {
    return (
      <div className="app-shell app-shell--center">
        <div className="card boot-error-card" role="alert">
          <h1 className="boot-error-card__title">Startup Error</h1>
          <p className="boot-error-card__msg">{bootError}</p>
          <button
            type="button"
            className="btn btn--primary"
            onClick={() => void loadBootstrap()}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      {!isWailsRuntime() && (
        <div className="preview-ribbon" role="note">
          Standalone UI Preview (mock backend)
        </div>
      )}

      {recovery && !recoveryDismissed && (
        <RecoveryBanner
          recovery={recovery}
          restoring={restoringNetwork}
          onRestoreNetwork={() => void handleRestoreNetwork()}
          onDismiss={() => setRecoveryDismissed(true)}
        />
      )}

      <HeaderBar
        profiles={profiles}
        activeProfile={activeProfile}
        disabled={isTunnelActive}
        onSelectProfile={(id) => setSelectedProfileId(id)}
        onNewProfile={() => setProfileModal({ open: true, profileId: null })}
        onEditProfile={() => {
          if (activeProfile) {
            setProfileModal({ open: true, profileId: activeProfile.id });
          }
        }}
        onOpenShare={() => setShareModalOpen(true)}
      />

      <main className="main-stack">
        <HeroConnectionCard
          status={status}
          activeProfile={activeProfile}
          busy={isTunnelActive ? disconnectBusy : connectBusy}
          onConnect={() => void handleConnect()}
          onDisconnect={() => void handleDisconnect()}
          onEditProfile={() => {
            if (activeProfile) {
              setProfileModal({ open: true, profileId: activeProfile.id });
            }
          }}
          onCreateProfile={() =>
            setProfileModal({ open: true, profileId: null })
          }
        />

        <ModeRoutingCard
          mode={activeMode}
          tunEnabled={tunEnabled}
          activeProfile={activeProfile}
          proxyCaps={proxyCaps}
          envSnippet={envSnippet}
          bypassBusy={bypassBusy}
          onModeChange={(nextMode) => {
            if (nextMode === "tun" && !tunEnabled) {
              return;
            }
            setActiveMode(nextMode);
          }}
          onToggleBypass={(bypass) => void handleToggleBypass(bypass)}
        />
      </main>

      {toast && (
        <div
          className={`toast toast--${toast.tone}`}
          role="status"
          aria-live="polite"
        >
          <span>{toast.message}</span>
        </div>
      )}

      <LogDrawer
        open={logsOpen}
        entries={logs}
        onClose={() => setLogsOpen(false)}
        onClear={handleClearLogs}
        onExportRedacted={() => api.ExportRedactedLogs()}
      />

      <FooterBar
        logsOpen={logsOpen}
        unreadSeverity={unreadSeverity}
        unreadCount={unreadCount}
        restoringNetwork={restoringNetwork}
        onToggleLogs={handleToggleLogs}
        onRestoreNetwork={() => void handleRestoreNetwork()}
      />

      <VaultUnlockModal
        open={vaultBackend === "encrypted-file" && vaultLocked}
        onUnlock={handleUnlockVault}
      />

      <ProfileModal
        open={profileModal.open}
        profile={editingProfile}
        onClose={() => setProfileModal({ open: false, profileId: null })}
        onSave={handleSaveProfile}
        onDelete={handleDeleteProfile}
        onClearHostKey={handleClearHostKey}
        onPickPrivateKey={() => api.PickPrivateKeyFile()}
      />

      <HostKeyModal
        prompt={hostKeyPrompt}
        busy={hostKeyBusy}
        onTrustAndConnect={handleTrustHostKeyAndConnect}
        onForgetAndReconnect={handleForgetAndReconnect}
        onCancel={handleCancelHostKey}
      />

      <ShareModal
        open={shareModalOpen}
        profiles={profiles}
        activeProfileId={activeProfile?.id ?? ""}
        onClose={() => setShareModalOpen(false)}
        onExport={handleExportShareLink}
        onInspect={handleInspectShareLink}
        onImport={handleImportProfile}
      />
    </div>
  );
}
