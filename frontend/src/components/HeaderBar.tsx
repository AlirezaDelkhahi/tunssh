import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import type { ProfileView } from "../api/bridge";
import {
  CheckIcon,
  ChevronDownIcon,
  EditIcon,
  LockIcon,
  PlusIcon,
  ShareIcon,
} from "./Icons";

interface HeaderBarProps {
  profiles: ProfileView[];
  activeProfile: ProfileView | null;
  disabled: boolean;
  onSelectProfile: (profileID: string) => void;
  onNewProfile: () => void;
  onEditProfile: () => void;
  onOpenShare: () => void;
}

export function HeaderBar({
  profiles,
  activeProfile,
  disabled,
  onSelectProfile,
  onNewProfile,
  onEditProfile,
  onOpenShare,
}: HeaderBarProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(0);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) {
      return undefined;
    }
    const handlePointerDown = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setMenuOpen(false);
      }
    };
    const handleKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        setMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [menuOpen]);

  const toggleMenu = () => {
    if (disabled || profiles.length === 0) {
      return;
    }
    if (!menuOpen) {
      const activeIdx = profiles.findIndex((p) => p.id === activeProfile?.id);
      setFocusedIndex(activeIdx >= 0 ? activeIdx : 0);
    }
    setMenuOpen((prev) => !prev);
  };

  const handleContainerKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (disabled || profiles.length === 0) {
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!menuOpen) {
        const activeIdx = profiles.findIndex((p) => p.id === activeProfile?.id);
        setFocusedIndex(activeIdx >= 0 ? activeIdx : 0);
        setMenuOpen(true);
        return;
      }
      setFocusedIndex((idx) =>
        e.key === "ArrowDown"
          ? (idx + 1) % profiles.length
          : (idx - 1 + profiles.length) % profiles.length,
      );
    } else if (e.key === "Enter" && menuOpen) {
      e.preventDefault();
      const target = profiles[focusedIndex];
      if (target) {
        onSelectProfile(target.id);
      }
      setMenuOpen(false);
    }
  };

  return (
    <header className="header-bar">
      <div
        className="profile-select"
        ref={dropdownRef}
        onKeyDown={handleContainerKeyDown}
      >
        <button
          type="button"
          className="profile-select__trigger"
          onClick={toggleMenu}
          disabled={disabled && profiles.length > 0}
          aria-haspopup="listbox"
          aria-expanded={menuOpen}
          aria-label={
            activeProfile
              ? `Selected profile ${activeProfile.name} (${activeProfile.host}:${activeProfile.port})`
              : "No profiles available"
          }
          title={
            disabled
              ? "Disconnect active tunnel to switch profiles"
              : activeProfile
                ? `${activeProfile.name} • ${activeProfile.host}:${activeProfile.port}`
                : "Create or import a profile"
          }
        >
          {activeProfile ? (
            <span className="profile-select__value">
              {activeProfile.pinned_host_key && (
                <span
                  className="tofu-badge"
                  title={`Pinned Host Key: ${activeProfile.pinned_host_key.algorithm} ${activeProfile.pinned_host_key.sha256}`}
                >
                  <LockIcon size={12} />
                </span>
              )}
              <span className="profile-select__name">{activeProfile.name}</span>
              <span className="profile-select__sep" aria-hidden="true">
                •
              </span>
              <span className="profile-select__endpoint" dir="ltr">
                {activeProfile.host}:{activeProfile.port}
              </span>
            </span>
          ) : (
            <span className="profile-select__empty">No profiles yet</span>
          )}
          <ChevronDownIcon size={14} className="profile-select__chevron" />
        </button>

        {menuOpen && profiles.length > 0 && (
          <ul
            className="profile-select__menu"
            role="listbox"
            aria-label="SSH tunnel profiles"
          >
            {profiles.map((profile, idx) => {
              const isSelected = profile.id === activeProfile?.id;
              const isHighlighted = idx === focusedIndex;
              return (
                <li key={profile.id} role="option" aria-selected={isSelected}>
                  <button
                    type="button"
                    className={`profile-select__option ${isSelected ? "is-selected" : ""} ${isHighlighted ? "is-highlighted" : ""}`}
                    onClick={() => {
                      onSelectProfile(profile.id);
                      setMenuOpen(false);
                    }}
                  >
                    <span className="profile-select__option-main">
                      {profile.pinned_host_key ? (
                        <span
                          className="tofu-badge"
                          title="Pinned SHA-256 host key"
                        >
                          <LockIcon size={12} />
                        </span>
                      ) : (
                        <span className="tofu-badge tofu-badge--unpinned" aria-hidden="true">
                          •
                        </span>
                      )}
                      <span className="profile-select__option-text">
                        <span className="profile-select__option-name">
                          {profile.name}
                        </span>
                        <span className="profile-select__option-host" dir="ltr">
                          {profile.username}@{profile.host}:{profile.port}
                        </span>
                      </span>
                    </span>
                    <span className="profile-select__option-meta">
                      <span className="mini-tag">
                        {profile.auth_type === "key" ? "KEY" : "PAM"}
                      </span>
                      {isSelected && <CheckIcon size={14} />}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      <div className="header-actions">
        <button
          type="button"
          className="action-chip action-chip--primary"
          onClick={onNewProfile}
          title="Add new SSH profile"
        >
          <PlusIcon size={13} />
          <span>New</span>
        </button>
        <button
          type="button"
          className="action-chip"
          onClick={onEditProfile}
          disabled={!activeProfile}
          title={
            activeProfile
              ? `Edit ${activeProfile.name}`
              : "Select a profile to edit"
          }
        >
          <EditIcon size={13} />
          <span>Edit</span>
        </button>
        <button
          type="button"
          className="action-chip"
          onClick={onOpenShare}
          title="Share or import sshtun:// link"
          aria-label="Share / Import"
        >
          <ShareIcon size={13} />
          <span>Share / Import</span>
        </button>
      </div>
    </header>
  );
}
