import React, { useState } from 'react';
import { Users, X, Check, Lock } from 'lucide-react';
import type { GroupMetadata } from '../../../server/src/types';

interface CreateGroupModalProps {
  currentUser: string;
  availableContacts: string[];
  onClose: () => void;
  onGroupCreated: (group: GroupMetadata) => void;
}

import { RELAY_URL } from '../config';
const SERVER_URL = RELAY_URL;

export function CreateGroupModal({
  currentUser,
  availableContacts,
  onClose,
  onGroupCreated,
}: CreateGroupModalProps) {
  const [groupName, setGroupName] = useState<string>('');
  const [selectedMembers, setSelectedMembers] = useState<Set<string>>(new Set());
  const [isCreating, setIsCreating] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  const otherContacts = availableContacts.filter(
    (c) => c.toLowerCase() !== currentUser.toLowerCase()
  );

  const toggleMember = (member: string) => {
    setSelectedMembers((prev) => {
      const next = new Set(prev);
      if (next.has(member)) {
        next.delete(member);
      } else {
        next.add(member);
      }
      return next;
    });
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupName.trim()) {
      setError('Please enter a group name.');
      return;
    }

    if (selectedMembers.size === 0) {
      setError('Please select at least one group member.');
      return;
    }

    setIsCreating(true);
    setError('');

    try {
      const members = Array.from(selectedMembers);
      const res = await fetch(`${SERVER_URL}/api/groups/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: groupName.trim(),
          creator: currentUser,
          members,
        }),
      });

      if (!res.ok) {
        throw new Error(`Failed to create group: ${res.statusText}`);
      }

      const groupData: GroupMetadata = await res.json();
      onGroupCreated(groupData);
      onClose();
    } catch (err) {
      console.error('Group creation error:', err);
      setError((err as Error).message);
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-3xl max-w-md w-full p-6 shadow-2xl space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-sky-500/20 text-sky-400 border border-sky-500/30 rounded-xl">
              <Users className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-white text-base">New Secret Group</h3>
              <p className="text-xs text-slate-400">Signal Sender Keys Protocol</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-xl hover:bg-slate-800 text-slate-400 hover:text-white transition-all"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {error && (
          <div className="p-2.5 rounded-xl bg-rose-950/70 border border-rose-800 text-rose-300 text-xs">
            {error}
          </div>
        )}

        <form onSubmit={handleCreate} className="space-y-4">
          {/* Group Name */}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-slate-300">Group Name</label>
            <input
              type="text"
              autoFocus
              value={groupName}
              onChange={(e) => setGroupName(e.target.value)}
              placeholder="e.g. Resistance Cell, Strategy Team..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
            />
          </div>

          {/* Member Selection */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
              <span>Select Members</span>
              <span className="text-[10px] text-slate-500 font-normal">
                {selectedMembers.size} selected
              </span>
            </label>

            <div className="max-h-48 overflow-y-auto space-y-1.5 bg-slate-950/60 p-2 rounded-xl border border-slate-800">
              {otherContacts.length === 0 ? (
                <div className="text-xs text-slate-500 text-center py-4">
                  No other registered users found.
                </div>
              ) : (
                otherContacts.map((contact) => {
                  const isSelected = selectedMembers.has(contact);

                  return (
                    <div
                      key={contact}
                      onClick={() => toggleMember(contact)}
                      className={`p-2 rounded-lg flex items-center justify-between cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-sky-600/20 border border-sky-500/50 text-white'
                          : 'hover:bg-slate-800/60 text-slate-300'
                      }`}
                    >
                      <div className="flex items-center gap-2.5">
                        <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-sky-600 to-indigo-600 flex items-center justify-center font-bold text-white text-xs">
                          {contact.charAt(0)}
                        </div>
                        <span className="text-xs font-medium">{contact}</span>
                      </div>

                      <div
                        className={`w-4 h-4 rounded-md border flex items-center justify-center transition-all ${
                          isSelected
                            ? 'bg-sky-600 border-sky-500 text-white'
                            : 'border-slate-700 bg-slate-900'
                        }`}
                      >
                        {isSelected && <Check className="w-3 h-3" />}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          <div className="p-3 bg-sky-950/30 border border-sky-900/40 rounded-xl flex items-center gap-2 text-[11px] text-slate-400">
            <Lock className="w-4 h-4 text-sky-400 shrink-0" />
            <span>
              Each member encrypts group broadcasts with their unique Sender Key. The server fans out single ciphertexts without deciphering.
            </span>
          </div>

          <div className="flex items-center justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 hover:bg-slate-800 text-slate-400 hover:text-white rounded-xl text-xs"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={isCreating || !groupName.trim() || selectedMembers.size === 0}
              className={`px-5 py-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs rounded-xl transition-all ${
                isCreating || !groupName.trim() || selectedMembers.size === 0
                  ? 'opacity-40 cursor-not-allowed'
                  : 'hover:scale-105'
              }`}
            >
              {isCreating ? 'Creating Group...' : 'Create Encrypted Group'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
