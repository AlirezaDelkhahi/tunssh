export interface HostKeyPinDTO {
  algorithm: string;
  sha256: string;
}

export interface ProfileView {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_type: "password" | "key";
  pinned_host_key?: HostKeyPinDTO | null;
  bypass_iran_lan: boolean;
  preferred_mode: "proxy" | "tun";
  has_secret: boolean;
  has_key_passphrase: boolean;
  created_at: string;
  updated_at: string;
}

export interface SaveProfileRequest {
  id?: string;
  name: string;
  host: string;
  port: number;
  username: string;
  auth_type: "password" | "key";
  bypass_iran_lan: boolean;
  preferred_mode: "proxy" | "tun";
  password?: string;
  private_key?: string;
  key_passphrase?: string;
  keep_existing_secrets: boolean;
}

export interface MappedErrorDTO {
  code: string;
  message: string;
  action_hint: string;
  retryable: boolean;
}

export type TunnelState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "reconnecting"
  | "error";

export interface TunnelStatusDTO {
  state: TunnelState;
  profile_id: string;
  mode: "proxy" | "tun";
  attempt: number;
  rtt_ms: number;
  rx_bytes: number;
  tx_bytes: number;
  rx_rate_bps: number;
  tx_rate_bps: number;
  connected_at_unix: number;
  socks_port: number;
  http_port: number;
  env_snippet: string;
  last_error?: MappedErrorDTO | null;
}

export interface HostKeyPromptDTO {
  profile_id: string;
  host: string;
  port: number;
  is_mismatch: boolean;
  algorithm: string;
  sha256: string;
  expected_algorithm?: string;
  expected_sha256?: string;
}

export interface LogEntryDTO {
  timestamp: string;
  level: "DEBUG" | "INFO" | "WARN" | "ERROR";
  message: string;
  code?: string;
  action_hint?: string;
}

export interface StartupRecoveryDTO {
  recovered: boolean;
  mode?: string;
  needs_elevation?: boolean;
  message?: string;
}

export interface ProxyCapabilitiesDTO {
  auto_supported: boolean;
  desktop_env: string;
}

export interface ShareInspectDTO {
  version: number;
  mode: "enc" | "plain";
  has_host_key: boolean;
}

export interface BootstrapStateDTO {
  vault_backend: "keyring" | "encrypted-file";
  vault_locked: boolean;
  proxy_caps: ProxyCapabilitiesDTO;
  status: TunnelStatusDTO;
  profiles: ProfileView[];
  recovery?: StartupRecoveryDTO | null;
  milestone: number;
  tun_enabled: boolean;
}

export interface AppServiceBindings {
  GetBootstrapState(): Promise<BootstrapStateDTO>;
  UnlockVault(passphrase: string): Promise<void>;
  ListProfiles(): Promise<ProfileView[]>;
  SaveProfile(req: SaveProfileRequest): Promise<ProfileView>;
  DeleteProfile(profileID: string): Promise<void>;
  ClearHostKey(profileID: string): Promise<ProfileView>;
  Connect(profileID: string, mode: string): Promise<void>;
  TrustHostKeyAndConnect(
    profileID: string,
    algorithm: string,
    sha256: string,
  ): Promise<void>;
  ForgetHostKey(profileID: string): Promise<ProfileView>;
  Disconnect(): Promise<void>;
  RestoreNetwork(): Promise<void>;
  SetBypassIranLAN(profileID: string, bypass: boolean): Promise<ProfileView>;
  ExportShareLink(
    profileID: string,
    passphrase: string,
    unsafePlain: boolean,
  ): Promise<string>;
  InspectShareLink(link: string): Promise<ShareInspectDTO>;
  ImportShareLink(
    link: string,
    passphrase: string,
    allowPlain: boolean,
  ): Promise<ProfileView>;
  GetLogs(): Promise<LogEntryDTO[]>;
  ClearLogs(): Promise<void>;
  ExportRedactedLogs(): Promise<string>;
  PickPrivateKeyFile(): Promise<string>;
  GetEnvSnippet(): Promise<string>;
}

export interface WailsEventMap {
  "tunnel:status": TunnelStatusDTO;
  "tunnel:stats": TunnelStatusDTO;
  "tunnel:hostkey_prompt": HostKeyPromptDTO;
  "tunnel:log": LogEntryDTO;
  "tunnel:recovery": StartupRecoveryDTO;
}

export type WailsEventName = keyof WailsEventMap;

interface WailsRuntime {
  EventsOn(
    eventName: string,
    callback: (...data: unknown[]) => void,
  ): (() => void) | void;
  EventsOff(eventName: string, ...additionalEventNames: string[]): void;
}

declare global {
  interface Window {
    go?: {
      app?: {
        AppService?: AppServiceBindings;
      };
    };
    runtime?: WailsRuntime;
  }
}

export function isWailsRuntime(): boolean {
  return Boolean(window.go?.app?.AppService);
}

export function formatBridgeError(err: unknown): string {
  if (typeof err === "string" && err.trim() !== "") {
    return err.trim();
  }
  if (err instanceof Error && err.message.trim() !== "") {
    return err.message.trim();
  }
  if (err && typeof err === "object" && "message" in err) {
    const msg = (err as { message?: unknown }).message;
    if (typeof msg === "string" && msg.trim() !== "") {
      return msg.trim();
    }
  }
  return "An unexpected error occurred.";
}

const DEFAULT_ENV_SNIPPET =
  "export ALL_PROXY=socks5h://127.0.0.1:10808 HTTP_PROXY=http://127.0.0.1:10809 HTTPS_PROXY=http://127.0.0.1:10809";

type GenericListener = (payload: unknown) => void;
const previewSubscribers = new Map<WailsEventName, Set<GenericListener>>();
const runtimeSubscribers = new Map<WailsEventName, Set<GenericListener>>();
const runtimeNativeCleanups = new Map<WailsEventName, () => void>();

function emitPreviewEvent<K extends WailsEventName>(
  event: K,
  payload: WailsEventMap[K],
): void {
  const listeners = previewSubscribers.get(event);
  if (!listeners) {
    return;
  }
  for (const fn of listeners) {
    fn(payload);
  }
}

function createPreviewAppService(): AppServiceBindings {
  const nowIso = () => new Date().toISOString();
  let profiles: ProfileView[] = [
    {
      id: "preview-de-443",
      name: "DE-443 (Preview)",
      host: "vps.example.com",
      port: 443,
      username: "tunnel",
      auth_type: "password",
      pinned_host_key: {
        algorithm: "ssh-ed25519",
        sha256: "SHA256:PreviewFingerprintExampleOnly000000000000",
      },
      bypass_iran_lan: true,
      preferred_mode: "proxy",
      has_secret: true,
      has_key_passphrase: false,
      created_at: nowIso(),
      updated_at: nowIso(),
    },
  ];

  let status: TunnelStatusDTO = {
    state: "disconnected",
    profile_id: profiles[0]?.id ?? "",
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
    env_snippet: DEFAULT_ENV_SNIPPET,
    last_error: null,
  };

  let logs: LogEntryDTO[] = [
    {
      timestamp: nowIso(),
      level: "INFO",
      message: "Standalone browser preview active (Wails Go backend not attached).",
    },
  ];

  let statsTimer: number | null = null;

  const stopTimer = () => {
    if (statsTimer !== null) {
      window.clearInterval(statsTimer);
      statsTimer = null;
    }
  };

  const pushLog = (entry: Omit<LogEntryDTO, "timestamp">) => {
    const full: LogEntryDTO = {
      timestamp: nowIso(),
      ...entry,
    };
    logs = [...logs.slice(-499), full];
    emitPreviewEvent("tunnel:log", full);
  };

  const setStatus = (next: TunnelStatusDTO) => {
    status = next;
    emitPreviewEvent("tunnel:status", next);
  };

  return {
    async GetBootstrapState(): Promise<BootstrapStateDTO> {
      return {
        vault_backend: "keyring",
        vault_locked: false,
        proxy_caps: {
          auto_supported: true,
          desktop_env: "preview",
        },
        status: { ...status },
        profiles: profiles.map((p) => ({ ...p })),
        recovery: null,
        milestone: 1,
        tun_enabled: false,
      };
    },
    async UnlockVault(_passphrase: string): Promise<void> {
      return;
    },
    async ListProfiles(): Promise<ProfileView[]> {
      return profiles.map((p) => ({ ...p }));
    },
    async SaveProfile(req: SaveProfileRequest): Promise<ProfileView> {
      const existingIdx = req.id
        ? profiles.findIndex((p) => p.id === req.id)
        : -1;
      const now = nowIso();
      if (existingIdx >= 0) {
        const existing = profiles[existingIdx]!;
        const updated: ProfileView = {
          ...existing,
          name: req.name.trim(),
          host: req.host.trim(),
          port: req.port,
          username: req.username.trim(),
          auth_type: req.auth_type,
          bypass_iran_lan: req.bypass_iran_lan,
          preferred_mode: req.preferred_mode,
          has_secret:
            req.keep_existing_secrets
              ? existing.has_secret
              : Boolean(req.password || req.private_key),
          has_key_passphrase:
            req.keep_existing_secrets
              ? existing.has_key_passphrase
              : Boolean(req.key_passphrase),
          updated_at: now,
        };
        profiles = profiles.map((p, idx) => (idx === existingIdx ? updated : p));
        pushLog({ level: "INFO", message: `Saved profile "${updated.name}".` });
        return { ...updated };
      }
      const created: ProfileView = {
        id: `preview-${Date.now().toString(36)}`,
        name: req.name.trim(),
        host: req.host.trim(),
        port: req.port,
        username: req.username.trim(),
        auth_type: req.auth_type,
        pinned_host_key: null,
        bypass_iran_lan: req.bypass_iran_lan,
        preferred_mode: req.preferred_mode,
        has_secret: Boolean(req.password || req.private_key),
        has_key_passphrase: Boolean(req.key_passphrase),
        created_at: now,
        updated_at: now,
      };
      profiles = [...profiles, created];
      pushLog({ level: "INFO", message: `Created profile "${created.name}".` });
      return { ...created };
    },
    async DeleteProfile(profileID: string): Promise<void> {
      profiles = profiles.filter((p) => p.id !== profileID);
      if (status.profile_id === profileID) {
        stopTimer();
        setStatus({
          ...status,
          state: "disconnected",
          profile_id: profiles[0]?.id ?? "",
          connected_at_unix: 0,
        });
      }
      pushLog({ level: "INFO", message: "Deleted profile in preview mode." });
    },
    async ClearHostKey(profileID: string): Promise<ProfileView> {
      const idx = profiles.findIndex((p) => p.id === profileID);
      if (idx < 0) {
        throw new Error("Profile not found");
      }
      const updated = {
        ...profiles[idx]!,
        pinned_host_key: null,
        updated_at: nowIso(),
      };
      profiles = profiles.map((p, i) => (i === idx ? updated : p));
      pushLog({
        level: "WARN",
        message: `Cleared pinned host key for "${updated.name}".`,
      });
      return { ...updated };
    },
    async Connect(profileID: string, mode: string): Promise<void> {
      const prof = profiles.find((p) => p.id === profileID);
      if (!prof) {
        throw new Error("Profile not found");
      }
      if (mode === "tun") {
        throw new Error("Full TUN mode is disabled in Milestone 1.");
      }
      stopTimer();
      setStatus({
        ...status,
        state: "connecting",
        profile_id: prof.id,
        mode: "proxy",
        attempt: 1,
        last_error: null,
      });
      pushLog({
        level: "INFO",
        message: `Connecting to ${prof.host}:${prof.port} via SSH (preview)...`,
      });

      window.setTimeout(() => {
        if (!prof.pinned_host_key) {
          setStatus({
            ...status,
            state: "disconnected",
            attempt: 0,
          });
          emitPreviewEvent("tunnel:hostkey_prompt", {
            profile_id: prof.id,
            host: prof.host,
            port: prof.port,
            is_mismatch: false,
            algorithm: "ssh-ed25519",
            sha256: "SHA256:PreviewTOFUServerKey000000000000000000",
          });
          return;
        }
        const connectedAt = Math.floor(Date.now() / 1000);
        setStatus({
          ...status,
          state: "connected",
          profile_id: prof.id,
          mode: "proxy",
          attempt: 0,
          rtt_ms: 48,
          connected_at_unix: connectedAt,
          last_error: null,
        });
        pushLog({
          level: "INFO",
          message: `Connected to ${prof.host}:${prof.port} (SOCKS5 :10808, HTTP :10809).`,
        });
        statsTimer = window.setInterval(() => {
          const rxRate = Math.floor(24000 + Math.random() * 140000);
          const txRate = Math.floor(4000 + Math.random() * 28000);
          status = {
            ...status,
            rtt_ms: Math.floor(42 + Math.random() * 18),
            rx_rate_bps: rxRate,
            tx_rate_bps: txRate,
            rx_bytes: status.rx_bytes + rxRate,
            tx_bytes: status.tx_bytes + txRate,
          };
          emitPreviewEvent("tunnel:stats", { ...status });
        }, 1000);
      }, 450);
    },
    async TrustHostKeyAndConnect(
      profileID: string,
      algorithm: string,
      sha256: string,
    ): Promise<void> {
      profiles = profiles.map((p) =>
        p.id === profileID
          ? {
              ...p,
              pinned_host_key: { algorithm, sha256 },
              updated_at: nowIso(),
            }
          : p,
      );
      pushLog({
        level: "INFO",
        message: `Trusted ${algorithm} host key ${sha256}.`,
      });
      await this.Connect(profileID, "proxy");
    },
    async ForgetHostKey(profileID: string): Promise<ProfileView> {
      return this.ClearHostKey(profileID);
    },
    async Disconnect(): Promise<void> {
      stopTimer();
      setStatus({
        ...status,
        state: "disconnected",
        attempt: 0,
        rtt_ms: 0,
        rx_rate_bps: 0,
        tx_rate_bps: 0,
        connected_at_unix: 0,
      });
      pushLog({ level: "INFO", message: "Tunnel disconnected." });
    },
    async RestoreNetwork(): Promise<void> {
      stopTimer();
      setStatus({
        ...status,
        state: "disconnected",
        attempt: 0,
        rtt_ms: 0,
        rx_rate_bps: 0,
        tx_rate_bps: 0,
        connected_at_unix: 0,
      });
      pushLog({
        level: "INFO",
        message: "OS system proxy settings verified and restored.",
      });
    },
    async SetBypassIranLAN(
      profileID: string,
      bypass: boolean,
    ): Promise<ProfileView> {
      const idx = profiles.findIndex((p) => p.id === profileID);
      if (idx < 0) {
        throw new Error("Profile not found");
      }
      const updated = {
        ...profiles[idx]!,
        bypass_iran_lan: bypass,
        updated_at: nowIso(),
      };
      profiles = profiles.map((p, i) => (i === idx ? updated : p));
      pushLog({
        level: "INFO",
        message: `Bypass Iran (.ir) & LAN ${bypass ? "enabled" : "disabled"} for "${updated.name}".`,
      });
      return { ...updated };
    },
    async ExportShareLink(
      profileID: string,
      passphrase: string,
      unsafePlain: boolean,
    ): Promise<string> {
      const prof = profiles.find((p) => p.id === profileID);
      if (!prof) {
        throw new Error("Profile not found");
      }
      if (!unsafePlain && !passphrase) {
        throw new Error("Passphrase is required for encrypted share links.");
      }
      const envelope = unsafePlain
        ? {
            v: 1,
            m: "plain",
            payload: {
              name: prof.name,
              host: prof.host,
              port: prof.port,
              user: prof.username,
              auth_type: prof.auth_type,
              secret: "[preview-redacted]",
              host_key: prof.pinned_host_key
                ? {
                    alg: prof.pinned_host_key.algorithm,
                    sha256: prof.pinned_host_key.sha256,
                  }
                : undefined,
            },
          }
        : {
            v: 1,
            m: "enc",
            kdf: "argon2id",
            preview_note: "Generated in browser preview mode",
            has_host_key: Boolean(prof.pinned_host_key),
          };
      const encoded = btoa(JSON.stringify(envelope))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
      return `sshtun://v1/${encoded}`;
    },
    async InspectShareLink(link: string): Promise<ShareInspectDTO> {
      const trimmed = link.trim();
      if (!trimmed.startsWith("sshtun://v1/")) {
        throw new Error("Invalid share link: must start with sshtun://v1/");
      }
      const b64 = trimmed.slice("sshtun://v1/".length).replace(/-/g, "+").replace(/_/g, "/");
      const parsed = JSON.parse(atob(b64)) as {
        v?: number;
        m?: string;
        has_host_key?: boolean;
        payload?: { host_key?: unknown };
      };
      if (parsed.v !== 1 || (parsed.m !== "enc" && parsed.m !== "plain")) {
        throw new Error("Unsupported share link version or mode.");
      }
      return {
        version: parsed.v,
        mode: parsed.m,
        has_host_key: Boolean(parsed.has_host_key ?? parsed.payload?.host_key),
      };
    },
    async ImportShareLink(
      link: string,
      passphrase: string,
      allowPlain: boolean,
    ): Promise<ProfileView> {
      const meta = await this.InspectShareLink(link);
      if (meta.mode === "plain" && !allowPlain) {
        throw new Error("Explicit confirmation required to import unencrypted link.");
      }
      if (meta.mode === "enc" && !passphrase) {
        throw new Error("Passphrase is required to decrypt share link.");
      }
      const imported: ProfileView = {
        id: `preview-import-${Date.now().toString(36)}`,
        name: "Imported Profile (Preview)",
        host: "imported.example.com",
        port: 443,
        username: "tunnel",
        auth_type: "password",
        pinned_host_key: meta.has_host_key
          ? {
              algorithm: "ssh-ed25519",
              sha256: "SHA256:ImportedHostKeyPreview000000000000000",
            }
          : null,
        bypass_iran_lan: true,
        preferred_mode: "proxy",
        has_secret: true,
        has_key_passphrase: false,
        created_at: nowIso(),
        updated_at: nowIso(),
      };
      profiles = [...profiles, imported];
      pushLog({ level: "INFO", message: `Imported profile "${imported.name}".` });
      return { ...imported };
    },
    async GetLogs(): Promise<LogEntryDTO[]> {
      return [...logs];
    },
    async ClearLogs(): Promise<void> {
      logs = [];
    },
    async ExportRedactedLogs(): Promise<string> {
      return logs
        .map(
          (l) =>
            `${l.timestamp} [${l.level}] ${l.code ? `${l.code}: ` : ""}${l.message}${l.action_hint ? ` | Hint: ${l.action_hint}` : ""}`,
        )
        .join("\n");
    },
    async PickPrivateKeyFile(): Promise<string> {
      return "";
    },
    async GetEnvSnippet(): Promise<string> {
      return DEFAULT_ENV_SNIPPET;
    },
  };
}

let previewSingleton: AppServiceBindings | null = null;

function getAppService(): AppServiceBindings {
  const nativeService = window.go?.app?.AppService;
  if (nativeService) {
    return nativeService;
  }
  if (!previewSingleton) {
    previewSingleton = createPreviewAppService();
  }
  return previewSingleton;
}

export const api: AppServiceBindings = {
  GetBootstrapState: () => getAppService().GetBootstrapState(),
  UnlockVault: (passphrase) => getAppService().UnlockVault(passphrase),
  ListProfiles: () => getAppService().ListProfiles(),
  SaveProfile: (req) => getAppService().SaveProfile(req),
  DeleteProfile: (profileID) => getAppService().DeleteProfile(profileID),
  ClearHostKey: (profileID) => getAppService().ClearHostKey(profileID),
  Connect: (profileID, mode) => getAppService().Connect(profileID, mode),
  TrustHostKeyAndConnect: (profileID, algorithm, sha256) =>
    getAppService().TrustHostKeyAndConnect(profileID, algorithm, sha256),
  ForgetHostKey: (profileID) => getAppService().ForgetHostKey(profileID),
  Disconnect: () => getAppService().Disconnect(),
  RestoreNetwork: () => getAppService().RestoreNetwork(),
  SetBypassIranLAN: (profileID, bypass) =>
    getAppService().SetBypassIranLAN(profileID, bypass),
  ExportShareLink: (profileID, passphrase, unsafePlain) =>
    getAppService().ExportShareLink(profileID, passphrase, unsafePlain),
  InspectShareLink: (link) => getAppService().InspectShareLink(link),
  ImportShareLink: (link, passphrase, allowPlain) =>
    getAppService().ImportShareLink(link, passphrase, allowPlain),
  GetLogs: () => getAppService().GetLogs(),
  ClearLogs: () => getAppService().ClearLogs(),
  ExportRedactedLogs: () => getAppService().ExportRedactedLogs(),
  PickPrivateKeyFile: () => getAppService().PickPrivateKeyFile(),
  GetEnvSnippet: () => getAppService().GetEnvSnippet(),
};

export function subscribeEvent<K extends WailsEventName>(
  eventName: K,
  handler: (payload: WailsEventMap[K]) => void,
): () => void {
  const runtime = window.runtime;
  if (runtime?.EventsOn) {
    let listeners = runtimeSubscribers.get(eventName);
    if (!listeners) {
      listeners = new Set();
      runtimeSubscribers.set(eventName, listeners);
    }

    const wrapped: GenericListener = (payload) => {
      handler(payload as WailsEventMap[K]);
    };
    listeners.add(wrapped);

    if (!runtimeNativeCleanups.has(eventName)) {
      const maybeUnsub = runtime.EventsOn(eventName, (data: unknown) => {
        const current = runtimeSubscribers.get(eventName);
        if (!current) {
          return;
        }
        for (const fn of current) {
          fn(data);
        }
      });
      runtimeNativeCleanups.set(eventName, () => {
        if (typeof maybeUnsub === "function") {
          maybeUnsub();
        } else {
          runtime.EventsOff?.(eventName);
        }
      });
    }

    return () => {
      const current = runtimeSubscribers.get(eventName);
      if (!current) {
        return;
      }
      current.delete(wrapped);
      if (current.size === 0) {
        runtimeSubscribers.delete(eventName);
        const cleanup = runtimeNativeCleanups.get(eventName);
        runtimeNativeCleanups.delete(eventName);
        cleanup?.();
      }
    };
  }

  // Fallback subscription for standalone Vite browser preview.
  let listeners = previewSubscribers.get(eventName);
  if (!listeners) {
    listeners = new Set();
    previewSubscribers.set(eventName, listeners);
  }
  const wrapped: GenericListener = (payload) => {
    handler(payload as WailsEventMap[K]);
  };
  listeners.add(wrapped);
  return () => {
    const current = previewSubscribers.get(eventName);
    if (!current) {
      return;
    }
    current.delete(wrapped);
    if (current.size === 0) {
      previewSubscribers.delete(eventName);
    }
  };
}
