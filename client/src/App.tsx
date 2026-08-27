import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Shield,
  ShieldCheck,
  KeyRound,
  Server,
  Send,
  User,
  Users,
  Lock,
  Eye,
  EyeOff,
  CheckCheck,
  CheckCircle2,
  RefreshCw,
  Flame,
  Settings,
  LockKeyhole,
  Paperclip,
  Mic,
  Plus,
  MessageSquare,
  Globe,
  Search,
  Pin,
  Smile,
  Phone,
  Video,
  Radio,
  QrCode,
} from 'lucide-react';
import { SessionManager } from './crypto/sessionManager';
import type { ChatMessage } from './crypto/sessionManager';
import type { RatchetStateSummary } from './crypto/doubleRatchet';
import { VaultSecurityManager } from './crypto/vault';
import { secureStore } from './crypto/secureStore';
import { AttachmentCrypto } from './crypto/attachments';
import { CryptographicInspector } from './components/CryptographicInspector';
import { SafetyNumberModal } from './components/SafetyNumberModal';
import { RelayTransparencyDrawer } from './components/RelayTransparencyDrawer';
import { OnboardingModal } from './components/OnboardingModal';
import { LockScreen } from './components/LockScreen';
import { SecuritySettingsModal } from './components/SecuritySettingsModal';
import { DisappearingTimerDropdown } from './components/DisappearingTimerDropdown';
import { EncryptedAttachmentView } from './components/EncryptedAttachmentView';
import { AudioRecorder } from './components/AudioRecorder';
import { CreateGroupModal } from './components/CreateGroupModal';
import { CensorshipModal } from './components/CensorshipModal';
import { ReactionPicker } from './components/ReactionPicker';
import { ChatSearchBar } from './components/ChatSearchBar';
import type { SearchFilterType } from './components/ChatSearchBar';
import { ThemeSelector } from './components/ThemeSelector';
import { PinnedMessageBanner } from './components/PinnedMessageBanner';
import { THEMES, ThemeManager } from './theme/themeConfig';
import type { AppTheme } from './theme/themeConfig';
import { WebRTCManager } from './crypto/webrtcManager';
import type { CallType, CallState } from './crypto/webrtcManager';
import { CallModal } from './components/CallModal';
import { IncomingCallModal } from './components/IncomingCallModal';
import { MeshNetwork } from './crypto/meshNetwork';
import type { DiscoveredPeer } from './crypto/meshNetwork';
import { MeshModal } from './components/MeshModal';
import { DevicePairingModal } from './components/DevicePairingModal';
import type { GroupMetadata } from '../../server/src/types';

const SERVER_URL = 'http://localhost:4000';

// Global cache of SessionManagers so switching profiles in demo retains state
const sessionManagersCache = new Map<string, SessionManager>();

function getOrCreateSessionManager(username: string): SessionManager {
  const key = username.toLowerCase();
  if (!sessionManagersCache.has(key)) {
    // Use the onboarded user's real seed phrase so their identity keys are
    // reproducible from the phrase on any device. Demo profiles fall back to a
    // deterministic per-username phrase inside SessionManager.
    const config = VaultSecurityManager.getConfig();
    const mnemonic =
      config && config.username.toLowerCase() === key
        ? VaultSecurityManager.getMnemonic() ?? undefined
        : undefined;
    const sm = new SessionManager(username, SERVER_URL, mnemonic);
    sessionManagersCache.set(key, sm);
  }
  return sessionManagersCache.get(key)!;
}

function loadSavedMessages(): ChatMessage[] {
  try {
    const saved = secureStore.getItem('aegis_chat_messages');
    return saved ? JSON.parse(saved) : [];
  } catch {
    return [];
  }
}

function saveMessages(msgs: ChatMessage[]): void {
  secureStore.setItem('aegis_chat_messages', JSON.stringify(msgs));
}

export function App() {
  const securityConfig = VaultSecurityManager.getConfig();
  const [hasConfig, setHasConfig] = useState<boolean>(Boolean(securityConfig));
  const [isLocked, setIsLocked] = useState<boolean>(VaultSecurityManager.isLocked());

  // Telegram / OLED Themes
  const [currentTheme, setCurrentTheme] = useState<AppTheme>(ThemeManager.getTheme);
  const theme = THEMES[currentTheme];

  const urlUser = new URLSearchParams(window.location.search).get('user');
  const initialUsername = securityConfig?.username || urlUser || 'Alice';
  const [currentUser, setCurrentUser] = useState<string>(initialUsername);

  // Chat navigation: Direct vs Groups
  const [activeTab, setActiveTab] = useState<'direct' | 'groups'>('direct');
  const [activeContact, setActiveContact] = useState<string>(currentUser.toLowerCase() === 'alice' ? 'Bob' : 'Alice');
  const [contacts, setContacts] = useState<string[]>(['Alice', 'Bob', 'Charlie']);
  const [groups, setGroups] = useState<GroupMetadata[]>([]);
  const [activeGroup, setActiveGroup] = useState<GroupMetadata | null>(null);
  const [showCreateGroupModal, setShowCreateGroupModal] = useState<boolean>(false);

  const [messages, setMessages] = useState<ChatMessage[]>(loadSavedMessages);
  const [inputText, setInputText] = useState<string>('');
  const [isConnected, setIsConnected] = useState<boolean>(false);
  const [isSending, setIsSending] = useState<boolean>(false);

  // Search & Filter in Chat
  const [showSearchBar, setShowSearchBar] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [searchFilterType, setSearchFilterType] = useState<SearchFilterType>('all');
  const [currentMatchIndex, setCurrentMatchIndex] = useState<number>(0);

  // Hovered message for reactions
  const [hoveredMsgId, setHoveredMsgId] = useState<string | null>(null);
  const [activePickerMsgId, setActivePickerMsgId] = useState<string | null>(null);

  // Attachments & Voice Notes
  const [isRecordingVoice, setIsRecordingVoice] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Security & Disappearing Messages
  const [disappearingTimerSec, setDisappearingTimerSec] = useState<number>(0);
  const [showSecurityModal, setShowSecurityModal] = useState<boolean>(false);
  const [showCensorshipModal, setShowCensorshipModal] = useState<boolean>(false);
  const [currentTime, setCurrentTime] = useState<number>(Date.now());

  // Inspector & Modal States
  const [showInspector, setShowInspector] = useState<boolean>(false);
  const [showSafetyModal, setShowSafetyModal] = useState<boolean>(false);
  const [showRelayLogs, setShowRelayLogs] = useState<boolean>(false);
  const [showDevicePairingModal, setShowDevicePairingModal] = useState<boolean>(false);
  const [verifiedContacts, setVerifiedContacts] = useState<Set<string>>(new Set());
  const [expandedCiphertexts, setExpandedCiphertexts] = useState<Set<string>>(new Set());

  // Live Cryptographic State
  const [ratchetSummary, setRatchetSummary] = useState<RatchetStateSummary | null>(null);
  const [showGroupMembers, setShowGroupMembers] = useState<boolean>(false);

  // WebRTC End-to-End Encrypted Calling
  const [callState, setCallState] = useState<CallState>('idle');
  const [callType, setCallType] = useState<CallType>('audio');
  const [activeCallPeer, setActiveCallPeer] = useState<string | null>(null);
  const [localStream, setLocalStream] = useState<MediaStream | null>(null);
  const [remoteStream, setRemoteStream] = useState<MediaStream | null>(null);
  const webrtcRef = useRef<WebRTCManager | null>(null);

  useEffect(() => {
    const wm = new WebRTCManager(
      async (peer, signal) => {
        if (smRef.current) {
          await smRef.current.sendCallSignal(peer, signal);
        }
      },
      (state) => {
        setCallState(state);
        if (state === 'idle') {
          setActiveCallPeer(null);
          setLocalStream(null);
          setRemoteStream(null);
        }
      },
      (stream) => {
        setRemoteStream(stream);
      }
    );
    webrtcRef.current = wm;

    return () => {
      wm.endCall();
    };
  }, []);

  // Offline P2P Mesh Network
  const [showMeshModal, setShowMeshModal] = useState<boolean>(false);
  const [isMeshEnabled, setIsMeshEnabled] = useState<boolean>(false);
  const [meshPeers, setMeshPeers] = useState<DiscoveredPeer[]>([]);
  const [meshRelayedCount, setMeshRelayedCount] = useState<number>(0);
  const meshRef = useRef<MeshNetwork | null>(null);

  useEffect(() => {
    const mn = new MeshNetwork(`node_${currentUser.toLowerCase()}`, currentUser);
    meshRef.current = mn;
    const unsub = mn.onPeersChanged((peers) => {
      setMeshPeers(peers);
      setMeshRelayedCount(mn.getRelayedCount());
    });

    return () => {
      unsub();
    };
  }, [currentUser]);

  const handleToggleMesh = (enabled: boolean) => {
    setIsMeshEnabled(enabled);
    meshRef.current?.setEnabled(enabled);
    if (enabled) {
      meshRef.current?.addOrUpdatePeer({
        id: 'node_charlie',
        username: 'Charlie (Local Ad-Hoc)',
        address: '192.168.1.42:42424',
        lastSeen: Date.now(),
        hopCount: 1,
      });
    }
  };

  const smRef = useRef<SessionManager | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const messageRefs = useRef<Map<string, HTMLDivElement>>(new Map());

  // Pre-register demo users
  useEffect(() => {
    getOrCreateSessionManager('Alice').registerOnRelay().catch(() => {});
    getOrCreateSessionManager('Bob').registerOnRelay().catch(() => {});
    getOrCreateSessionManager('Charlie').registerOnRelay().catch(() => {});
  }, []);

  // Fetch groups for current user
  const fetchUserGroups = async () => {
    try {
      const res = await fetch(`${SERVER_URL}/api/groups/user/${encodeURIComponent(currentUser)}`);
      if (res.ok) {
        const { groups: userGroups } = await res.json();
        setGroups(userGroups || []);
        if (userGroups && userGroups.length > 0 && !activeGroup) {
          setActiveGroup(userGroups[0]);
        }
      }
    } catch (err) {
      console.error('Failed to fetch user groups:', err);
    }
  };

  useEffect(() => {
    fetchUserGroups();
  }, [currentUser]);

  // Ticker for auto-lock & disappearing messages
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      setCurrentTime(now);

      if (hasConfig && !isLocked && VaultSecurityManager.isLocked()) {
        VaultSecurityManager.lock();
        setIsLocked(true);
      }

      setMessages((prev) => {
        const remaining = prev.filter((m) => !m.expiresAt || m.expiresAt > now);
        if (remaining.length !== prev.length) {
          saveMessages(remaining);
          return remaining;
        }
        return prev;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [hasConfig, isLocked]);

  const handleUserActivity = () => {
    VaultSecurityManager.touchActivity();
  };

  // Initialize and switch users
  useEffect(() => {
    let active = true;

    // Don't spin up the crypto session engine until the encrypted-at-rest store
    // is open (i.e. the vault is unlocked), or we'd derive keys with no access
    // to the persisted seed phrase / sessions.
    if (hasConfig && (isLocked || !secureStore.isUnlocked())) {
      return;
    }

    async function initUser() {
      if (smRef.current) {
        smRef.current.disconnect();
      }

      // Now that storage is readable, hydrate persisted history.
      setMessages(loadSavedMessages());

      const sm = getOrCreateSessionManager(currentUser);
      smRef.current = sm;
      // Enforce out-of-band safety-number verification before the first message.
      sm.requireVerificationBeforeSend = true;
      // Reflect persisted pin state in the UI badges.
      setVerifiedContacts(() => {
        const s = new Set<string>();
        for (const c of contacts) {
          if (sm.getPeerTrustState(c) === 'verified') s.add(c);
        }
        return s;
      });

      try {
        await sm.registerOnRelay();

        sm.connectWebSocket(
          (incomingMsg) => {
            if (!active) return;
            setMessages((prev) => {
              // Check if incoming is a reaction update
              try {
                if (incomingMsg.text?.startsWith('{"_aegisReaction":true,')) {
                  const parsed = JSON.parse(incomingMsg.text);
                  return prev.map((m) => {
                    if (m.id === parsed.messageId) {
                      const reactions = { ...(m.reactions || {}) };
                      const users = reactions[parsed.emoji] || [];
                      if (!users.includes(incomingMsg.sender)) {
                        reactions[parsed.emoji] = [...users, incomingMsg.sender];
                      }
                      return { ...m, reactions };
                    }
                    return m;
                  });
                }

                // Check if incoming is a pin update
                if (incomingMsg.text?.startsWith('{"_aegisPin":true,')) {
                  const parsed = JSON.parse(incomingMsg.text);
                  return prev.map((m) =>
                    m.id === parsed.messageId ? { ...m, isPinned: parsed.isPinned } : m
                  );
                }
              } catch {
                // Regular chat message
              }

              const exists = prev.some((m) => m.id === incomingMsg.id);
              const updated = exists
                ? prev.map((m) => (m.id === incomingMsg.id ? incomingMsg : m))
                : [...prev, incomingMsg];
              saveMessages(updated);
              return updated;
            });
          },
          (peer, summary) => {
            if (!active) return;
            if (peer.toLowerCase() === activeContact.toLowerCase()) {
              setRatchetSummary(summary);
            }
          },
          (connected) => {
            if (!active) return;
            setIsConnected(connected);
          }
        );

        sm.setOnCallSignal((peer, signal) => {
          if (!active) return;
          if (signal.type === 'CALL_INVITE') {
            setActiveCallPeer(peer);
            setCallType(signal.callType);
          }
          webrtcRef.current?.handleSignal(peer, signal);
          if (webrtcRef.current?.localStream) {
            setLocalStream(webrtcRef.current.localStream);
          }
        });

        const usersRes = await fetch(`${SERVER_URL}/api/users`);
        if (usersRes.ok) {
          const { users } = await usersRes.json();
          if (users && users.length > 0) {
            setContacts((prev) => Array.from(new Set([...prev, ...users])));
          }
        }
      } catch (err) {
        console.error('Failed to initialize user session:', err);
      }
    }

    initUser();

    if (currentUser.toLowerCase() === 'alice') {
      setActiveContact('Bob');
    } else if (currentUser.toLowerCase() === 'bob') {
      setActiveContact('Alice');
    }

    return () => {
      active = false;
    };
  }, [currentUser, isLocked, hasConfig]);

  // Update ratchet summary
  useEffect(() => {
    if (smRef.current && activeContact && activeTab === 'direct') {
      const summary = smRef.current.getRatchetSummary(activeContact);
      setRatchetSummary(summary);
    }
  }, [activeContact, activeTab, messages]);

  // Scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, activeTab, activeContact, activeGroup]);

  const isGroupCreator =
    !!activeGroup && activeGroup.creator.toLowerCase() === currentUser.toLowerCase();

  const handleRemoveGroupMember = async (member: string) => {
    if (!activeGroup || !smRef.current) return;
    if (
      !confirm(
        `Remove ${member} from "${activeGroup.name}"? Your sender key will rotate so ` +
        `they cannot read any further messages.`
      )
    ) {
      return;
    }
    try {
      await smRef.current.removeGroupMember(activeGroup.id, member, activeGroup.members);
      const updated: GroupMetadata = {
        ...activeGroup,
        members: activeGroup.members.filter(
          (m) => m.toLowerCase() !== member.toLowerCase()
        ),
      };
      setActiveGroup(updated);
      setGroups((prev) => prev.map((g) => (g.id === updated.id ? updated : g)));
    } catch (err) {
      alert('Could not remove member: ' + (err as Error).message);
    }
  };

  // Handle group created
  const handleGroupCreated = async (newGroup: GroupMetadata) => {
    setGroups((prev) => [...prev, newGroup]);
    setActiveGroup(newGroup);
    setActiveTab('groups');

    if (smRef.current) {
      await smRef.current.distributeSenderKeyToGroup(newGroup.id, newGroup.members);
    }
  };

  // Send regular text message
  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!inputText.trim() || !smRef.current || isSending) return;

    handleUserActivity();
    const text = inputText.trim();
    setInputText('');
    setIsSending(true);

    try {
      let sentMsg: ChatMessage;

      if (activeTab === 'groups' && activeGroup) {
        sentMsg = await smRef.current.sendGroupMessage(
          activeGroup.id,
          text,
          disappearingTimerSec
        );
      } else {
        sentMsg = await smRef.current.sendMessage(
          activeContact,
          text,
          disappearingTimerSec
        );
      }

      setMessages((prev) => {
        const exists = prev.some((m) => m.id === sentMsg.id);
        const updated = exists ? prev : [...prev, sentMsg];
        saveMessages(updated);
        return updated;
      });

      if (activeTab === 'direct') {
        const summary = smRef.current.getRatchetSummary(activeContact);
        if (summary) setRatchetSummary(summary);
      }
    } catch (err) {
      const msg = (err as Error).message || '';
      console.error('Failed to send encrypted message:', err);
      if (msg.startsWith('VERIFICATION_REQUIRED')) {
        setInputText(text); // don't lose what they typed
        setShowSafetyModal(true);
        alert(
          `Verify ${activeContact}'s safety number before sending your first message. ` +
          `Compare the numbers in person or over another trusted channel, then tap "Mark Verified".`
        );
      } else if (msg.startsWith('IDENTITY_CHANGED')) {
        setInputText(text);
        setShowSafetyModal(true);
        alert(
          `⚠️ SECURITY WARNING: ${activeContact}'s identity key has CHANGED since you last ` +
          `verified it. This can happen if they reinstalled — or it can be an attacker ` +
          `intercepting your messages. Do NOT send anything sensitive until you re-verify ` +
          `the safety number with them directly.`
        );
      } else {
        alert('Error sending message: ' + msg);
      }
    } finally {
      setIsSending(false);
    }
  };

  // Send encrypted file attachment
  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !smRef.current || isSending) return;

    handleUserActivity();
    setIsSending(true);

    try {
      const descriptor = await AttachmentCrypto.encryptAndUpload(
        file,
        file.name,
        false,
        undefined,
        SERVER_URL
      );

      let sentMsg: ChatMessage;
      if (activeTab === 'groups' && activeGroup) {
        sentMsg = await smRef.current.sendGroupMessage(
          activeGroup.id,
          file.name,
          disappearingTimerSec,
          descriptor
        );
      } else {
        sentMsg = await smRef.current.sendMessage(
          activeContact,
          file.name,
          disappearingTimerSec,
          descriptor
        );
      }

      setMessages((prev) => {
        const updated = [...prev, sentMsg];
        saveMessages(updated);
        return updated;
      });
    } catch (err) {
      console.error('Failed to send encrypted file:', err);
      alert('Failed to send attachment: ' + (err as Error).message);
    } finally {
      setIsSending(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // Send encrypted voice note
  const handleVoiceComplete = async (audioBlob: Blob, durationSec: number) => {
    if (!smRef.current || isSending) return;

    handleUserActivity();
    setIsSending(true);
    setIsRecordingVoice(false);

    try {
      const descriptor = await AttachmentCrypto.encryptAndUpload(
        audioBlob,
        'voice-memo.webm',
        true,
        durationSec,
        SERVER_URL
      );

      let sentMsg: ChatMessage;
      if (activeTab === 'groups' && activeGroup) {
        sentMsg = await smRef.current.sendGroupMessage(
          activeGroup.id,
          '🎙️ Voice Note',
          disappearingTimerSec,
          descriptor
        );
      } else {
        sentMsg = await smRef.current.sendMessage(
          activeContact,
          '🎙️ Voice Note',
          disappearingTimerSec,
          descriptor
        );
      }

      setMessages((prev) => {
        const updated = [...prev, sentMsg];
        saveMessages(updated);
        return updated;
      });
    } catch (err) {
      console.error('Failed to send encrypted voice note:', err);
      alert('Failed to send voice note: ' + (err as Error).message);
    } finally {
      setIsSending(false);
    }
  };

  // Toggle Emoji Reaction on a message
  const handleToggleReaction = async (msgId: string, emoji: string) => {
    handleUserActivity();

    // 1. Update state locally
    setMessages((prev) => {
      const updated = prev.map((m) => {
        if (m.id === msgId) {
          const reactions = { ...(m.reactions || {}) };
          const users = reactions[emoji] || [];
          if (users.includes(currentUser)) {
            reactions[emoji] = users.filter((u) => u !== currentUser);
          } else {
            reactions[emoji] = [...users, currentUser];
          }
          return { ...m, reactions };
        }
        return m;
      });
      saveMessages(updated);
      return updated;
    });

    // 2. Broadcast encrypted reaction packet
    const payload = JSON.stringify({ _aegisReaction: true, messageId: msgId, emoji });
    try {
      if (activeTab === 'groups' && activeGroup && smRef.current) {
        await smRef.current.sendGroupMessage(activeGroup.id, payload, 0);
      } else if (smRef.current) {
        await smRef.current.sendMessage(activeContact, payload, 0);
      }
    } catch (err) {
      console.warn('Failed to broadcast reaction:', err);
    }
  };

  // Toggle Pin message
  const handleTogglePin = async (msgId: string) => {
    handleUserActivity();

    let nextPinState = true;
    setMessages((prev) => {
      const updated = prev.map((m) => {
        if (m.id === msgId) {
          nextPinState = !m.isPinned;
          return { ...m, isPinned: nextPinState };
        }
        // Only one pinned message per chat at a time for clean UX
        return { ...m, isPinned: false };
      });
      saveMessages(updated);
      return updated;
    });

    const payload = JSON.stringify({ _aegisPin: true, messageId: msgId, isPinned: nextPinState });
    try {
      if (activeTab === 'groups' && activeGroup && smRef.current) {
        await smRef.current.sendGroupMessage(activeGroup.id, payload, 0);
      } else if (smRef.current) {
        await smRef.current.sendMessage(activeContact, payload, 0);
      }
    } catch (err) {
      console.warn('Failed to broadcast pin state:', err);
    }
  };

  const handleStartCall = async (type: CallType) => {
    if (!activeContact || !webrtcRef.current) return;
    setActiveCallPeer(activeContact);
    setCallType(type);
    await webrtcRef.current.startCall(activeContact, type);
    setLocalStream(webrtcRef.current.localStream);
  };

  const handleAcceptCall = async () => {
    if (!webrtcRef.current) return;
    await webrtcRef.current.acceptCall();
    setLocalStream(webrtcRef.current.localStream);
  };

  const handleDeclineCall = async () => {
    if (!webrtcRef.current) return;
    await webrtcRef.current.declineCall();
  };

  const handleEndCall = () => {
    webrtcRef.current?.endCall();
  };

  const handleJumpToMessage = (msgId: string) => {
    const el = messageRefs.current.get(msgId);
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      el.classList.add('ring-2', 'ring-sky-400');
      setTimeout(() => el.classList.remove('ring-2', 'ring-sky-400'), 2000);
    }
  };

  const toggleVerifyContact = async (contact: string) => {
    const nowVerified = !verifiedContacts.has(contact);
    try {
      if (nowVerified) {
        // User confirmed the safety number out-of-band: pin the current
        // directory key as verified (also resolves a prior key change).
        await smRef.current?.markPeerVerified(contact, true);
      } else {
        smRef.current?.setPeerVerified(contact, false);
      }
    } catch (err) {
      alert('Could not update verification: ' + (err as Error).message);
      return;
    }
    setVerifiedContacts((prev) => {
      const updated = new Set(prev);
      if (nowVerified) updated.add(contact);
      else updated.delete(contact);
      return updated;
    });
  };

  const toggleCiphertext = (msgId: string) => {
    setExpandedCiphertexts((prev) => {
      const updated = new Set(prev);
      if (updated.has(msgId)) {
        updated.delete(msgId);
      } else {
        updated.add(msgId);
      }
      return updated;
    });
  };

  const clearChatHistory = () => {
    if (confirm('Clear local encrypted chat history?')) {
      secureStore.removeItem('aegis_chat_messages');
      setMessages([]);
    }
  };

  const handlePanicShred = () => {
    VaultSecurityManager.lock();
    setMessages([]);
    setHasConfig(false);
    setIsLocked(false);
    sessionManagersCache.clear();
    if (smRef.current) smRef.current.disconnect();
  };

  // Base message stream for active conversation
  const rawChatMessages = useMemo(() => {
    return messages.filter((m) => {
      // Don't render protocol packets
      if (
        m.text?.startsWith('{"_aegisReaction":true,') ||
        m.text?.startsWith('{"_aegisPin":true,') ||
        m.text?.startsWith('{"_aegisGroupDistribution":true,')
      ) {
        return false;
      }

      if (activeTab === 'groups' && activeGroup) {
        return m.groupId === activeGroup.id;
      }
      return (
        !m.groupId &&
        ((m.sender.toLowerCase() === currentUser.toLowerCase() &&
          m.recipient.toLowerCase() === activeContact.toLowerCase()) ||
          (m.sender.toLowerCase() === activeContact.toLowerCase() &&
            m.recipient.toLowerCase() === currentUser.toLowerCase()))
      );
    });
  }, [messages, activeTab, activeGroup, activeContact, currentUser]);

  // Filtered messages based on search bar
  const currentChatMessages = useMemo(() => {
    if (!showSearchBar) return rawChatMessages;

    return rawChatMessages.filter((m) => {
      // Type filter
      if (searchFilterType === 'media' && !m.attachment?.fileType.startsWith('image/')) {
        return false;
      }
      if (searchFilterType === 'voice' && !m.attachment?.isVoiceNote) {
        return false;
      }

      // Query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const textMatch = m.text?.toLowerCase().includes(q);
        const fileMatch = m.attachment?.fileName.toLowerCase().includes(q);
        return textMatch || fileMatch;
      }

      return true;
    });
  }, [rawChatMessages, showSearchBar, searchQuery, searchFilterType]);

  // Find currently pinned message
  const pinnedMessage = useMemo(() => {
    return rawChatMessages.find((m) => m.isPinned);
  }, [rawChatMessages]);

  const safetyNumberData =
    smRef.current && activeTab === 'direct'
      ? smRef.current.getSafetyNumber(activeContact)
      : null;

  // Render Onboarding Modal if not set up yet
  if (!hasConfig) {
    return (
      <OnboardingModal
        onComplete={(newUsername) => {
          setCurrentUser(newUsername);
          setHasConfig(true);
          setIsLocked(false);
        }}
      />
    );
  }

  // Render Lock Screen if vault is locked
  if (isLocked) {
    return (
      <LockScreen
        username={currentUser}
        onUnlock={() => {
          VaultSecurityManager.touchActivity();
          setIsLocked(false);
        }}
        onDuressShred={handlePanicShred}
      />
    );
  }

  return (
    <div
      onMouseMove={handleUserActivity}
      onKeyDown={handleUserActivity}
      className={`flex h-screen w-screen ${theme.appBg} text-slate-100 overflow-hidden select-none transition-colors duration-300`}
    >
      {/* Hidden File Picker */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileSelect}
        className="hidden"
      />

      {/* SIDEBAR */}
      <div className={`w-80 border-r ${theme.border} ${theme.sidebarBg} flex flex-col transition-colors duration-300`}>
        {/* Profile Card & Switcher */}
        <div className={`p-4 border-b ${theme.border} ${theme.sidebarBg} space-y-3`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-sky-500/20 text-sky-400 border border-sky-500/30">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-base font-bold text-white tracking-tight flex items-center gap-1.5">
                  AegisChat <span className="text-[10px] bg-sky-950 text-sky-400 px-1.5 py-0.5 rounded border border-sky-800/50">E2EE</span>
                </h1>
                <p className="text-[11px] text-slate-400">Zero-Anchor · Telegram UI</p>
              </div>
            </div>

            {/* Top Right Actions: Theme, Lock, Settings */}
            <div className="flex items-center gap-0.5">
              <ThemeSelector
                currentTheme={currentTheme}
                onSelectTheme={(t) => {
                  setCurrentTheme(t);
                  ThemeManager.setTheme(t);
                }}
              />
              <button
                onClick={() => setShowDevicePairingModal(true)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-sky-300 transition-all"
                title="Linked Devices & Multi-Device Sync (QR)"
              >
                <QrCode className="w-4 h-4" />
              </button>
              <button
                onClick={() => { VaultSecurityManager.lock(); setIsLocked(true); }}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-sky-300 transition-all"
                title="Lock Vault Immediately"
              >
                <LockKeyhole className="w-4 h-4" />
              </button>
              <button
                onClick={() => setShowSecurityModal(true)}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
                title="Security & Anti-Forensics Settings"
              >
                <Settings className="w-4 h-4" />
              </button>
              <div
                className={`w-2.5 h-2.5 rounded-full ml-1 ${
                  isConnected ? 'bg-emerald-400 shadow-lg shadow-emerald-500/50' : 'bg-rose-500'
                }`}
                title={isConnected ? 'Connected to Blind Relay' : 'Disconnected'}
              />
            </div>
          </div>

          {/* Quick Profile Switcher */}
          <div className={`${theme.cardBg} p-2 rounded-xl border ${theme.border}`}>
            <div className="text-[10px] uppercase tracking-wider text-slate-400 font-semibold mb-1 flex items-center justify-between">
              <span>Active Identity:</span>
              <span className="text-emerald-400 font-mono text-[10px]">ECDH Loaded</span>
            </div>
            <div className="grid grid-cols-3 gap-1">
              {['Alice', 'Bob', 'Charlie'].map((user) => (
                <button
                  key={user}
                  onClick={() => {
                    setCurrentUser(user);
                    window.history.replaceState(null, '', `?user=${user}`);
                  }}
                  className={`px-2 py-1.5 rounded-lg text-xs font-semibold flex items-center justify-center gap-1 transition-all ${
                    currentUser.toLowerCase() === user.toLowerCase()
                      ? `${theme.accentBg} font-bold shadow-md`
                      : 'bg-black/20 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <User className="w-3 h-3" />
                  <span>{user}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Tab Switcher: Direct Chats vs Secret Groups */}
        <div className={`grid grid-cols-2 p-1.5 ${theme.cardBg} border-b ${theme.border} gap-1 text-xs font-semibold`}>
          <button
            onClick={() => setActiveTab('direct')}
            className={`py-1.5 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              activeTab === 'direct'
                ? 'bg-slate-800/90 text-white shadow-sm font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>Direct (1:1)</span>
          </button>

          <button
            onClick={() => setActiveTab('groups')}
            className={`py-1.5 rounded-lg flex items-center justify-center gap-1.5 transition-all ${
              activeTab === 'groups'
                ? 'bg-slate-800/90 text-white shadow-sm font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Users className="w-3.5 h-3.5" />
            <span>Groups ({groups.length})</span>
          </button>
        </div>

        {/* LIST AREA */}
        <div className="flex-1 overflow-y-auto divide-y divide-slate-800/30">
          {activeTab === 'direct' ? (
            contacts
              .filter((c) => c.toLowerCase() !== currentUser.toLowerCase())
              .map((contact) => {
                const isSelected = activeContact.toLowerCase() === contact.toLowerCase();
                const isVerified = verifiedContacts.has(contact);

                return (
                  <div
                    key={contact}
                    onClick={() => setActiveContact(contact)}
                    className={`p-3.5 flex items-center gap-3 cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-slate-800/90 border-l-4 border-sky-500 text-white'
                        : 'hover:bg-slate-800/40 text-slate-300'
                    }`}
                  >
                    <div className="relative">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center font-bold text-white shadow-md">
                        {contact.charAt(0)}
                      </div>
                      {isVerified && (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 absolute -bottom-0.5 -right-0.5 bg-slate-900 rounded-full" />
                      )}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-sm truncate flex items-center gap-1">
                          {contact}
                          {isVerified && (
                            <span className="text-[10px] text-emerald-400 bg-emerald-950/80 px-1 rounded border border-emerald-800/50">
                              Verified
                            </span>
                          )}
                        </span>
                        <span className="text-[10px] text-slate-400">E2EE</span>
                      </div>
                      <p className="text-xs text-slate-400 truncate mt-0.5 flex items-center gap-1">
                        <Lock className="w-2.5 h-2.5 text-sky-400" />
                        <span>Double Ratchet Channel</span>
                      </p>
                    </div>
                  </div>
                );
              })
          ) : (
            <div className="space-y-1 p-2">
              <button
                onClick={() => setShowCreateGroupModal(true)}
                className="w-full py-2.5 px-3 rounded-xl bg-sky-950/40 hover:bg-sky-900/40 border border-sky-800/50 text-sky-300 text-xs font-semibold flex items-center justify-center gap-2 transition-all mb-2 shadow-sm"
              >
                <Plus className="w-4 h-4" />
                <span>Create Secret Group</span>
              </button>

              {groups.length === 0 ? (
                <div className="text-xs text-slate-500 text-center py-6">
                  No secret groups yet. Click above to create one.
                </div>
              ) : (
                groups.map((group) => {
                  const isSelected = activeGroup?.id === group.id;

                  return (
                    <div
                      key={group.id}
                      onClick={() => setActiveGroup(group)}
                      className={`p-3 rounded-xl flex items-center gap-3 cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-slate-800 text-white border-l-4 border-sky-500'
                          : 'hover:bg-slate-800/40 text-slate-300'
                      }`}
                    >
                      <div className="w-9 h-9 rounded-xl bg-indigo-600/30 text-indigo-400 border border-indigo-500/40 flex items-center justify-center font-bold text-sm">
                        <Users className="w-4 h-4" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-xs text-white truncate">{group.name}</span>
                          <span className="text-[10px] text-slate-500">{group.members.length} members</span>
                        </div>
                        <p className="text-[10px] text-slate-400 truncate mt-0.5">
                          {group.members.join(', ')}
                        </p>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          )}
        </div>

        {/* Action Triggers in Sidebar */}
        <div className={`p-3 border-t ${theme.border} ${theme.sidebarBg} space-y-2`}>
          <button
            onClick={() => setShowRelayLogs(true)}
            className="w-full py-2 px-3 rounded-xl bg-black/30 hover:bg-slate-800 border border-slate-800 text-xs font-semibold text-indigo-300 flex items-center justify-center gap-2 transition-all"
          >
            <Server className="w-4 h-4 text-indigo-400" />
            <span>Relay Transparency Log</span>
          </button>
          <button
            onClick={clearChatHistory}
            className="w-full py-1.5 px-3 rounded-xl hover:bg-slate-800/60 text-[11px] text-slate-500 hover:text-slate-400 transition-all"
          >
            Clear Local Chat History
          </button>
        </div>
      </div>

      {/* MAIN CHAT AREA */}
      <div className={`flex-1 flex flex-col ${theme.chatBg} relative transition-colors duration-300`}>
        {/* Chat Top Bar */}
        <div className={`h-16 px-6 border-b ${theme.border} ${theme.topBarBg} backdrop-blur-md flex items-center justify-between z-10`}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center font-bold text-white shadow-md">
              {activeTab === 'groups' ? (
                <Users className="w-5 h-5" />
              ) : (
                activeContact.charAt(0)
              )}
            </div>
            <div>
              <div className="flex items-center gap-1.5 font-bold text-base text-white">
                <span>{activeTab === 'groups' ? (activeGroup?.name || 'Group Chat') : activeContact}</span>
                {activeTab === 'direct' && verifiedContacts.has(activeContact) ? (
                  <span title="Cryptographically Verified">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  </span>
                ) : null}
              </div>
              <div className="text-[11px] text-slate-400 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                <span>
                  {activeTab === 'groups'
                    ? `Sender Keys Ratchet (${activeGroup?.members.length || 0} Members)`
                    : 'Zero-Knowledge Blind Relay'}
                </span>
                {activeTab === 'direct' && ratchetSummary && (
                  <span className={`${theme.accentText} font-mono`}>
                    · Ratchet #{ratchetSummary.ratchetStep}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-1.5">
            {/* In-Chat Search Button */}
            <button
              onClick={() => setShowSearchBar(!showSearchBar)}
              className={`p-2 rounded-xl border text-xs transition-all ${
                showSearchBar
                  ? 'bg-sky-600 border-sky-500 text-white'
                  : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-white'
              }`}
              title="Search encrypted messages & media"
            >
              <Search className="w-4 h-4" />
            </button>

            {/* Disappearing Message Timer */}
            <DisappearingTimerDropdown
              currentTimerSec={disappearingTimerSec}
              onSelectTimer={setDisappearingTimerSec}
            />

            {/* Censorship Bypass Button */}
            <button
              onClick={() => setShowCensorshipModal(true)}
              className="px-3 py-1.5 rounded-xl bg-indigo-950/50 hover:bg-indigo-900/50 border border-indigo-800/60 text-xs font-semibold text-indigo-300 flex items-center gap-1.5 transition-all"
              title="Tor SOCKS5 & Censorship Bypass"
            >
              <Globe className="w-4 h-4 text-indigo-400" />
              <span>Bypass</span>
            </button>

            {/* Offline Mesh Network Button */}
            <button
              onClick={() => setShowMeshModal(true)}
              className={`px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all ${
                isMeshEnabled
                  ? 'bg-emerald-950/60 border-emerald-500 text-emerald-300 shadow-sm'
                  : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:text-white'
              }`}
              title="Offline Ad-Hoc Mesh Network"
            >
              <Radio className={`w-4 h-4 ${isMeshEnabled ? 'text-emerald-400 animate-pulse' : 'text-slate-400'}`} />
              <span>{isMeshEnabled ? 'Mesh: ON' : 'Mesh'}</span>
            </button>

            {activeTab === 'direct' ? (
              <>
                {/* E2EE Audio & Video Call Triggers */}
                <button
                  type="button"
                  onClick={() => handleStartCall('audio')}
                  className="p-2 rounded-xl bg-slate-900/60 border border-slate-800 text-slate-300 hover:text-emerald-400 hover:border-emerald-500/50 hover:bg-emerald-950/30 transition-all"
                  title="Encrypted Voice Call (WebRTC P2P)"
                >
                  <Phone className="w-4 h-4" />
                </button>

                <button
                  type="button"
                  onClick={() => handleStartCall('video')}
                  className="p-2 rounded-xl bg-slate-900/60 border border-slate-800 text-slate-300 hover:text-sky-400 hover:border-sky-500/50 hover:bg-sky-950/30 transition-all"
                  title="Encrypted Video Call (WebRTC P2P)"
                >
                  <Video className="w-4 h-4" />
                </button>

                <button
                  onClick={() => setShowSafetyModal(true)}
                  className={`px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all ${
                    verifiedContacts.has(activeContact)
                      ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300 hover:bg-emerald-900/40'
                      : 'bg-slate-800/80 border-slate-700/80 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>Safety Number</span>
                </button>

                <button
                  onClick={() => setShowInspector(!showInspector)}
                  className="px-3 py-1.5 rounded-xl bg-sky-950/50 hover:bg-sky-900/50 border border-sky-800/60 text-xs font-semibold text-sky-300 flex items-center gap-1.5 transition-all"
                >
                  <KeyRound className="w-4 h-4 text-sky-400" />
                  <span>Inspect Crypto</span>
                </button>
              </>
            ) : (
              <>
                <span className="text-xs bg-indigo-950 text-indigo-300 px-3 py-1.5 rounded-xl border border-indigo-800/50 font-mono flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Sender Keys</span>
                </span>
                <button
                  onClick={() => setShowGroupMembers((v) => !v)}
                  className={`px-3 py-1.5 rounded-xl border text-xs font-semibold flex items-center gap-1.5 transition-all ${
                    showGroupMembers
                      ? 'bg-sky-600 border-sky-500 text-white'
                      : 'bg-slate-900/60 border-slate-800 text-slate-300 hover:text-white'
                  }`}
                  title="Group members"
                >
                  <Users className="w-3.5 h-3.5" />
                  <span>Members</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Group members panel */}
        {activeTab === 'groups' && showGroupMembers && activeGroup && (
          <div className="px-6 py-3 border-b border-slate-800 bg-slate-900/60">
            <div className="text-[11px] uppercase tracking-wide text-slate-400 mb-2">
              Members ({activeGroup.members.length})
              {isGroupCreator && (
                <span className="ml-2 text-slate-500 normal-case tracking-normal">
                  · removing a member rotates your sender key
                </span>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              {activeGroup.members.map((m) => (
                <span
                  key={m}
                  className="flex items-center gap-1.5 text-xs bg-slate-800 border border-slate-700 rounded-lg px-2 py-1 text-slate-200"
                >
                  <span>{m}</span>
                  {m.toLowerCase() === activeGroup.creator.toLowerCase() && (
                    <span className="text-[9px] text-amber-400">creator</span>
                  )}
                  {isGroupCreator && m.toLowerCase() !== currentUser.toLowerCase() && (
                    <button
                      onClick={() => handleRemoveGroupMember(m)}
                      className="text-rose-400 hover:text-rose-300 font-bold leading-none"
                      title={`Remove ${m}`}
                    >
                      ×
                    </button>
                  )}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* In-Chat Search Drawer */}
        {showSearchBar && (
          <ChatSearchBar
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            filterType={searchFilterType}
            onFilterTypeChange={setSearchFilterType}
            totalMatches={currentChatMessages.length}
            currentMatchIndex={currentMatchIndex}
            onNextMatch={() => {
              if (currentChatMessages.length > 0) {
                const nextIdx = (currentMatchIndex + 1) % currentChatMessages.length;
                setCurrentMatchIndex(nextIdx);
                handleJumpToMessage(currentChatMessages[nextIdx].id);
              }
            }}
            onPrevMatch={() => {
              if (currentChatMessages.length > 0) {
                const prevIdx = (currentMatchIndex - 1 + currentChatMessages.length) % currentChatMessages.length;
                setCurrentMatchIndex(prevIdx);
                handleJumpToMessage(currentChatMessages[prevIdx].id);
              }
            }}
            onClose={() => {
              setShowSearchBar(false);
              setSearchQuery('');
            }}
          />
        )}

        {/* Sticky Pinned Message Banner */}
        {pinnedMessage && (
          <PinnedMessageBanner
            pinnedMessage={pinnedMessage}
            onJumpToMessage={handleJumpToMessage}
            onUnpin={handleTogglePin}
          />
        )}

        {/* Message Stream */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {currentChatMessages.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-slate-500 space-y-3">
              <div className="p-4 rounded-2xl bg-black/30 border border-slate-800 text-sky-400">
                <Lock className="w-8 h-8" />
              </div>
              <p className="text-sm font-medium text-slate-300">
                {activeTab === 'groups'
                  ? `Encrypted Group: ${activeGroup?.name || ''}`
                  : `End-to-End Encrypted Session with ${activeContact}`}
              </p>
              <p className="text-xs text-slate-400 max-w-sm text-center leading-relaxed">
                {activeTab === 'groups'
                  ? 'Messages in this group are protected by the Signal Sender Keys Protocol with Ed25519 digital signatures and ChaCha20-Poly1305 forward secrecy.'
                  : `Messages and attachments between you and ${activeContact} are protected with X3DH key exchange and Double Ratchet forward secrecy.`}
              </p>
            </div>
          ) : (
            currentChatMessages.map((msg) => {
              const isSender = msg.sender.toLowerCase() === currentUser.toLowerCase();
              const isExpanded = expandedCiphertexts.has(msg.id);
              const isHovered = hoveredMsgId === msg.id;

              const timeLeftSec = msg.expiresAt
                ? Math.max(0, Math.ceil((msg.expiresAt - currentTime) / 1000))
                : null;

              return (
                <div
                  key={msg.id}
                  ref={(el) => {
                    if (el) messageRefs.current.set(msg.id, el);
                    else messageRefs.current.delete(msg.id);
                  }}
                  onMouseEnter={() => setHoveredMsgId(msg.id)}
                  onMouseLeave={() => {
                    setHoveredMsgId(null);
                    if (activePickerMsgId === msg.id) setActivePickerMsgId(null);
                  }}
                  className={`flex flex-col relative group transition-all rounded-2xl ${
                    isSender ? 'items-end' : 'items-start'
                  }`}
                >
                  {!isSender && (
                    <span className="text-[10px] font-semibold px-2 mb-0.5 flex items-center gap-1 text-sky-400">
                      <span>{msg.sender}</span>
                      {activeTab === 'groups' && (
                        <span className="text-[9px] text-slate-500 font-normal">in {activeGroup?.name}</span>
                      )}
                    </span>
                  )}

                  {/* Reaction / Action Floating Bar */}
                  {isHovered && (
                    <div
                      className={`absolute -top-7 flex items-center gap-1 z-20 animate-fadeIn ${
                        isSender ? 'right-2' : 'left-2'
                      }`}
                    >
                      {/* Emoji Trigger */}
                      <button
                        type="button"
                        onClick={() =>
                          setActivePickerMsgId(activePickerMsgId === msg.id ? null : msg.id)
                        }
                        className="p-1 bg-slate-900/90 border border-slate-700/80 rounded-full text-slate-300 hover:text-amber-400 hover:scale-110 transition-all shadow-md"
                        title="React with Emoji"
                      >
                        <Smile className="w-3.5 h-3.5" />
                      </button>

                      {/* Pin Message Trigger */}
                      <button
                        type="button"
                        onClick={() => handleTogglePin(msg.id)}
                        className={`p-1 bg-slate-900/90 border border-slate-700/80 rounded-full hover:scale-110 transition-all shadow-md ${
                          msg.isPinned ? 'text-sky-400' : 'text-slate-300 hover:text-sky-400'
                        }`}
                        title={msg.isPinned ? 'Unpin message' : 'Pin message'}
                      >
                        <Pin className="w-3.5 h-3.5" />
                      </button>

                      {/* Reaction Picker Popover */}
                      {activePickerMsgId === msg.id && (
                        <ReactionPicker
                          isSender={isSender}
                          onSelectReaction={(emoji) => {
                            handleToggleReaction(msg.id, emoji);
                            setActivePickerMsgId(null);
                          }}
                          onClose={() => setActivePickerMsgId(null)}
                        />
                      )}
                    </div>
                  )}

                  {/* Message Bubble */}
                  <div
                    className={`max-w-[75%] rounded-2xl px-4 py-2.5 shadow-md relative transition-all ${
                      isSender
                        ? `${theme.senderBubbleBg} rounded-br-none`
                        : `${theme.recipientBubbleBg} rounded-bl-none`
                    } ${msg.isPinned ? 'ring-1 ring-sky-400/50' : ''}`}
                  >
                    {/* Encrypted Attachment (Image, Voice, File) */}
                    {msg.attachment && (
                      <EncryptedAttachmentView
                        descriptor={msg.attachment}
                        isSender={isSender}
                      />
                    )}

                    {/* Text Message with Search Query Highlight */}
                    {msg.text && (!msg.attachment || msg.attachment.fileName !== msg.text) && (
                      <div className={`text-sm leading-relaxed break-words ${msg.attachment ? 'mt-1.5' : ''}`}>
                        {searchQuery.trim() && msg.text.toLowerCase().includes(searchQuery.toLowerCase()) ? (
                          <span className="bg-amber-400/30 text-amber-200 px-0.5 rounded">
                            {msg.text}
                          </span>
                        ) : (
                          msg.text
                        )}
                      </div>
                    )}

                    {/* Bubble Footer */}
                    <div className="flex items-center justify-end gap-2 mt-1 pt-1 text-[10px] opacity-80">
                      {msg.isPinned && (
                        <span title="Pinned">
                          <Pin className="w-2.5 h-2.5 fill-current text-sky-300" />
                        </span>
                      )}

                      <span className="font-mono">
                        {new Date(msg.timestamp).toLocaleTimeString([], {
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </span>

                      {/* Self-Destruct Countdown Badge */}
                      {timeLeftSec !== null && (
                        <span className="flex items-center gap-0.5 bg-amber-950/80 border border-amber-800/60 text-amber-300 px-1.5 py-0.2 rounded text-[9px] font-mono">
                          <Flame className="w-2.5 h-2.5 text-amber-400 animate-pulse" />
                          <span>{timeLeftSec}s</span>
                        </span>
                      )}

                      {isSender && <CheckCheck className="w-3.5 h-3.5 text-sky-200" />}
                      <span className="bg-black/20 px-1.5 py-0.2 rounded text-[9px] font-mono">
                        {activeTab === 'groups' ? `Key #${msg.ratchetStep}` : `Ratchet #${msg.ratchetStep}`}
                      </span>
                    </div>
                  </div>

                  {/* Emoji Reactions Pill Badges */}
                  {msg.reactions && Object.keys(msg.reactions).length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-1 px-1">
                      {Object.entries(msg.reactions).map(([emoji, users]) => {
                        if (users.length === 0) return null;
                        const hasReacted = users.includes(currentUser);

                        return (
                          <button
                            key={emoji}
                            type="button"
                            onClick={() => handleToggleReaction(msg.id, emoji)}
                            className={`px-2 py-0.5 rounded-full text-xs flex items-center gap-1 border transition-all ${
                              hasReacted
                                ? 'bg-sky-600/30 border-sky-500 text-sky-200 font-semibold'
                                : 'bg-slate-900/80 border-slate-700/80 text-slate-300 hover:border-slate-600'
                            }`}
                            title={`Reacted by: ${users.join(', ')}`}
                          >
                            <span>{emoji}</span>
                            <span className="text-[10px] font-mono">{users.length}</span>
                          </button>
                        );
                      })}
                    </div>
                  )}

                  {/* Toggle Ciphertext Inspector */}
                  <button
                    onClick={() => toggleCiphertext(msg.id)}
                    className="mt-1 text-[10px] text-slate-500 hover:text-sky-400 flex items-center gap-1 transition-colors px-1"
                  >
                    {isExpanded ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    <span>{isExpanded ? 'Hide Ciphertext' : 'Inspect Ciphertext'}</span>
                  </button>

                  {isExpanded && (
                    <div className="mt-1 max-w-[75%] bg-slate-950 p-2.5 rounded-xl border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
                      <div className="text-[10px] uppercase font-bold text-sky-400">
                        {activeTab === 'groups' ? 'Sender Key Payload & Ed25519 Signature:' : 'ChaCha20-Poly1305 Payload:'}
                      </div>
                      <div className="break-all text-amber-200/90">{msg.rawCiphertextPreview}</div>
                      <div className="text-[9px] text-slate-600">Pure ciphertext forwarded by relay without deciphering.</div>
                    </div>
                  )}
                </div>
              );
            })
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Message Input Bar */}
        <div className={`p-4 border-t ${theme.border} ${theme.topBarBg} backdrop-blur-md`}>
          {isRecordingVoice ? (
            <AudioRecorder
              onRecordingComplete={handleVoiceComplete}
              onCancel={() => setIsRecordingVoice(false)}
            />
          ) : (
            <form onSubmit={handleSendMessage} className="flex items-center gap-2">
              {/* Attachment Picker Button */}
              <button
                type="button"
                disabled={isSending}
                onClick={() => fileInputRef.current?.click()}
                className="p-3 rounded-xl bg-black/30 hover:bg-slate-800 text-slate-400 hover:text-sky-400 border border-slate-800 transition-all"
                title="Send Encrypted Image or Document"
              >
                <Paperclip className="w-4 h-4" />
              </button>

              {/* Voice Note Button */}
              <button
                type="button"
                disabled={isSending}
                onClick={() => setIsRecordingVoice(true)}
                className="p-3 rounded-xl bg-black/30 hover:bg-slate-800 text-slate-400 hover:text-rose-400 border border-slate-800 transition-all"
                title="Record Encrypted Voice Memo"
              >
                <Mic className="w-4 h-4" />
              </button>

              {/* Text Input */}
              <div className="flex-1 relative flex items-center">
                <input
                  type="text"
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value)}
                  placeholder={
                    activeTab === 'groups'
                      ? `Send encrypted message to ${activeGroup?.name || 'group'}...`
                      : `Send uncrackable message to ${activeContact}...`
                  }
                  className={`w-full ${theme.inputBg} border ${theme.border} rounded-xl px-4 py-3 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition-all shadow-inner`}
                />
                <div className="absolute right-3 flex items-center gap-1.5 text-[10px] text-slate-400 font-mono bg-black/40 px-2 py-1 rounded-md border border-slate-800">
                  {disappearingTimerSec > 0 && (
                    <span className="flex items-center gap-1 text-amber-400">
                      <Flame className="w-3 h-3" />
                      <span>{disappearingTimerSec}s Timer</span>
                    </span>
                  )}
                  <Lock className="w-3 h-3 text-sky-400" />
                  <span>{activeTab === 'groups' ? 'Sender Keys' : 'E2EE Active'}</span>
                </div>
              </div>

              {/* Send Button */}
              <button
                type="submit"
                disabled={!inputText.trim() || isSending}
                className={`p-3 rounded-xl ${theme.accentBg} font-semibold shadow-lg transition-all ${
                  !inputText.trim() || isSending ? 'opacity-40 cursor-not-allowed' : 'hover:scale-105 active:scale-95'
                }`}
              >
                {isSending ? <RefreshCw className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
              </button>
            </form>
          )}
        </div>
      </div>

      {/* Create Group Modal */}
      {showCreateGroupModal && (
        <CreateGroupModal
          currentUser={currentUser}
          availableContacts={contacts}
          onClose={() => setShowCreateGroupModal(false)}
          onGroupCreated={handleGroupCreated}
        />
      )}

      {/* Cryptographic Ratchet Inspector Drawer */}
      {showInspector && (
        <CryptographicInspector
          summary={ratchetSummary}
          currentUser={currentUser}
          peerUser={activeContact}
          onClose={() => setShowInspector(false)}
        />
      )}

      {/* Safety Number Fingerprint Modal */}
      {showSafetyModal && (
        <SafetyNumberModal
          currentUser={currentUser}
          peerUser={activeContact}
          safetyNumber={safetyNumberData}
          isVerified={verifiedContacts.has(activeContact)}
          onToggleVerify={() => toggleVerifyContact(activeContact)}
          onClose={() => setShowSafetyModal(false)}
        />
      )}

      {/* Blind Relay Transparency Drawer */}
      {showRelayLogs && (
        <RelayTransparencyDrawer
          serverUrl={SERVER_URL}
          onClose={() => setShowRelayLogs(false)}
        />
      )}

      {/* Security & Anti-Forensic Settings Modal */}
      {showSecurityModal && (
        <SecuritySettingsModal
          onClose={() => setShowSecurityModal(false)}
          onEmergencyShred={handlePanicShred}
        />
      )}

      {/* Censorship Bypass & Tor Transport Modal */}
      {showCensorshipModal && (
        <CensorshipModal
          serverUrl={SERVER_URL}
          onClose={() => setShowCensorshipModal(false)}
        />
      )}

      {/* Incoming Call Modal */}
      {callState === 'incoming_ringing' && activeCallPeer && (
        <IncomingCallModal
          caller={activeCallPeer}
          callType={callType}
          onAccept={handleAcceptCall}
          onDecline={handleDeclineCall}
        />
      )}

      {/* Active Call Modal */}
      {callState !== 'idle' && callState !== 'incoming_ringing' && activeCallPeer && (
        <CallModal
          peer={activeCallPeer}
          callType={callType}
          callState={callState}
          localStream={localStream}
          remoteStream={remoteStream}
          onToggleMute={() => webrtcRef.current?.toggleMuteAudio() || false}
          onToggleVideo={() => webrtcRef.current?.toggleVideo() || false}
          onEndCall={handleEndCall}
        />
      )}

      {/* Offline P2P Mesh Modal */}
      {showMeshModal && (
        <MeshModal
          isEnabled={isMeshEnabled}
          onToggleMesh={handleToggleMesh}
          peers={meshPeers}
          relayedCount={meshRelayedCount}
          onClose={() => setShowMeshModal(false)}
        />
      )}

      {/* Linked Devices & Multi-Device Pairing Modal */}
      {showDevicePairingModal && (
        <DevicePairingModal
          currentUser={currentUser}
          onClose={() => setShowDevicePairingModal(false)}
        />
      )}
    </div>
  );
}

export default App;
