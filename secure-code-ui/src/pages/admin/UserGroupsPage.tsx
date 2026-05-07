// secure-code-ui/src/pages/admin/UserGroupsPage.tsx
//
// Admin CRUD + membership management for user groups. Groups are the
// foundation of the scan-scope filter: members of a group can see each
// other's scans. Admins still see everything.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import React, { useState } from "react";
import type { UserGroup } from "../../shared/api/userGroupService";
import { userGroupService } from "../../shared/api/userGroupService";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";
import { useToast } from "../../shared/ui/Toast";

interface GroupForm {
  name: string;
  description: string;
}

const EMPTY_FORM: GroupForm = { name: "", description: "" };

function apiDetail(err: unknown): string {
  if (err instanceof AxiosError) {
    const detail = (err.response?.data as { detail?: string })?.detail;
    if (detail) return detail;
  }
  return "Unknown error";
}

const UserGroupsPage: React.FC = () => {
  const toast = useToast();
  const qc = useQueryClient();

  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState<UserGroup | null>(null);
  const [form, setForm] = useState<GroupForm>(EMPTY_FORM);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [activeGroupId, setActiveGroupId] = useState<string | null>(null);
  const [memberEmail, setMemberEmail] = useState("");

  const { data: groups, isLoading, isError, error } = useQuery<
    UserGroup[],
    Error
  >({
    queryKey: ["user-groups"],
    queryFn: userGroupService.list,
  });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["user-groups"] });

  const createMutation = useMutation({
    mutationFn: userGroupService.create,
    onSuccess: () => {
      toast.success("Group created.");
      invalidate();
      closeModal();
    },
    onError: (err) => toast.error(`Create failed: ${apiDetail(err)}`),
  });

  const updateMutation = useMutation({
    mutationFn: (args: { id: string; values: GroupForm }) =>
      userGroupService.update(args.id, args.values),
    onSuccess: () => {
      toast.success("Group updated.");
      invalidate();
      closeModal();
    },
    onError: (err) => toast.error(`Update failed: ${apiDetail(err)}`),
  });

  const deleteMutation = useMutation({
    mutationFn: userGroupService.remove,
    onSuccess: () => {
      toast.success("Group deleted.");
      invalidate();
      setConfirmDeleteId(null);
      if (activeGroupId === confirmDeleteId) {
        setActiveGroupId(null);
      }
    },
    onError: (err) => toast.error(`Delete failed: ${apiDetail(err)}`),
  });

  const addMemberMutation = useMutation({
    mutationFn: (args: { id: string; email: string }) =>
      userGroupService.addMember(args.id, { email: args.email }),
    onSuccess: () => {
      toast.success("Member added.");
      setMemberEmail("");
      invalidate();
    },
    onError: (err) => toast.error(`Add member failed: ${apiDetail(err)}`),
  });

  const removeMemberMutation = useMutation({
    mutationFn: (args: { id: string; userId: number }) =>
      userGroupService.removeMember(args.id, args.userId),
    onSuccess: () => {
      toast.success("Member removed.");
      invalidate();
    },
    onError: (err) => toast.error(`Remove failed: ${apiDetail(err)}`),
  });

  const closeModal = () => {
    setModalOpen(false);
    setEditing(null);
    setForm(EMPTY_FORM);
  };

  const openCreateModal = () => {
    setEditing(null);
    setForm(EMPTY_FORM);
    setModalOpen(true);
  };

  const openEditModal = (g: UserGroup) => {
    setEditing(g);
    setForm({ name: g.name, description: g.description ?? "" });
    setModalOpen(true);
  };

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.name.trim()) {
      toast.error("Group name is required.");
      return;
    }
    if (form.name.trim().length > 64) {
      toast.error("Group name must be 64 characters or fewer.");
      return;
    }
    if (form.description.trim().length > 512) {
      toast.error("Description must be 512 characters or fewer.");
      return;
    }
    if (editing) {
      updateMutation.mutate({
        id: editing.id,
        values: {
          name: form.name.trim(),
          description: form.description.trim(),
        },
      });
    } else {
      createMutation.mutate({
        name: form.name.trim(),
        description: form.description.trim() || null,
      });
    }
  };

  const pending = createMutation.isPending || updateMutation.isPending;
  const activeGroup =
    activeGroupId && groups
      ? groups.find((g) => g.id === activeGroupId) ?? null
      : null;

  if (isError) {
    toast.error(`Failed to load groups: ${error.message}`);
  }

  return (
    <div className="fade-in" style={{ display: "grid", gap: 16 }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-end",
          gap: 12,
        }}
      >
        <div>
          <h1 style={{ color: "var(--fg)" }}>User groups</h1>
          <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
            Members of a group can see each other's scans. Admins see
            everything.
          </div>
        </div>
        <button
          className="sccap-btn sccap-btn-primary"
          onClick={openCreateModal}
        >
          <Icon.Plus size={13} /> Create group
        </button>
      </div>

      {isLoading ? (
        <div
          className="sccap-card"
          style={{
            padding: 40,
            textAlign: "center",
            color: "var(--fg-muted)",
          }}
        >
          Loading groups…
        </div>
      ) : !groups || groups.length === 0 ? (
        <div
          className="sccap-card"
          style={{ padding: 60, textAlign: "center" }}
        >
          <div style={{ color: "var(--fg)", fontWeight: 500, marginBottom: 4 }}>
            No groups yet
          </div>
          <div style={{ color: "var(--fg-muted)", fontSize: 13 }}>
            Create a group to let members share visibility of each other's
            scans.
          </div>
        </div>
      ) : (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))",
            gap: 14,
          }}
        >
          {groups.map((g) => (
            <div key={g.id} className="sccap-card">
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                  marginBottom: 10,
                }}
              >
                <div>
                  <div
                    style={{
                      fontSize: 10.5,
                      color: "var(--fg-subtle)",
                      textTransform: "uppercase",
                      letterSpacing: ".06em",
                    }}
                  >
                    Group
                  </div>
                  <div
                    style={{
                      fontWeight: 600,
                      color: "var(--fg)",
                      marginTop: 2,
                    }}
                  >
                    {g.name}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    aria-label="Edit"
                    onClick={() => openEditModal(g)}
                  >
                    <Icon.Edit size={13} />
                  </button>
                  <button
                    className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                    aria-label="Delete"
                    style={{ color: "var(--critical)" }}
                    onClick={() => setConfirmDeleteId(g.id)}
                  >
                    <Icon.Trash size={13} />
                  </button>
                </div>
              </div>
              <div
                style={{
                  fontSize: 12.5,
                  color: "var(--fg-muted)",
                  lineHeight: 1.5,
                  marginBottom: 12,
                  minHeight: 36,
                }}
              >
                {g.description || (
                  <span style={{ color: "var(--fg-subtle)" }}>
                    No description
                  </span>
                )}
              </div>
              <div
                style={{
                  fontSize: 10.5,
                  color: "var(--fg-subtle)",
                  textTransform: "uppercase",
                  letterSpacing: ".06em",
                  marginBottom: 6,
                }}
              >
                {g.member_count} member{g.member_count === 1 ? "" : "s"}
              </div>
              <button
                className="sccap-btn sccap-btn-sm"
                onClick={() => setActiveGroupId(g.id)}
              >
                Manage members
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Create / edit modal */}
      <Modal
        open={modalOpen}
        onClose={closeModal}
        title={editing ? "Edit group" : "Create group"}
        width={480}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={closeModal}
              disabled={pending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={onSubmit}
              disabled={pending}
            >
              {pending
                ? "Saving…"
                : editing
                  ? "Save changes"
                  : "Create group"}
            </button>
          </>
        }
      >
        <form onSubmit={onSubmit} style={{ display: "grid", gap: 14 }}>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Group name
            </span>
            <input
              className="sccap-input"
              placeholder="e.g. Platform Team"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
              autoFocus
              maxLength={64}
            />
          </label>
          <label style={{ display: "grid", gap: 6 }}>
            <span style={{ fontSize: 12, color: "var(--fg-muted)" }}>
              Description (optional)
            </span>
            <textarea
              className="sccap-input"
              rows={3}
              placeholder="What does this group represent?"
              value={form.description}
              onChange={(e) =>
                setForm({ ...form, description: e.target.value })
              }
              maxLength={512}
            />
          </label>
          <button type="submit" style={{ display: "none" }} />
        </form>
      </Modal>

      {/* Delete confirm */}
      <Modal
        open={confirmDeleteId !== null}
        onClose={() => setConfirmDeleteId(null)}
        title="Delete group?"
        width={420}
        footer={
          <>
            <button
              className="sccap-btn sccap-btn-sm"
              onClick={() => setConfirmDeleteId(null)}
              disabled={deleteMutation.isPending}
            >
              Cancel
            </button>
            <button
              className="sccap-btn sccap-btn-danger sccap-btn-sm"
              onClick={() =>
                confirmDeleteId &&
                deleteMutation.mutate(confirmDeleteId)
              }
              disabled={deleteMutation.isPending}
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete"}
            </button>
          </>
        }
      >
        <div style={{ fontSize: 13, color: "var(--fg-muted)" }}>
          Members of this group will lose visibility of each other's scans.
          This doesn't delete any user accounts or scans.
        </div>
      </Modal>

      {/* Members drawer */}
      <Modal
        open={activeGroup !== null}
        onClose={() => {
          setActiveGroupId(null);
          setMemberEmail("");
        }}
        title={activeGroup ? `Members — ${activeGroup.name}` : "Members"}
        width={560}
      >
        {activeGroup && (
          <div style={{ display: "grid", gap: 14 }}>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const trimmedEmail = memberEmail.trim();
                if (!trimmedEmail) return;
                if (trimmedEmail.length > 254) {
                  toast.error("Email address is too long.");
                  return;
                }
                if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmedEmail)) {
                  toast.error("Please enter a valid email address.");
                  return;
                }
                addMemberMutation.mutate({
                  id: activeGroup.id,
                  email: trimmedEmail,
                });
              }}
              style={{ display: "flex", gap: 8 }}
            >
              <input
                className="sccap-input"
                type="email"
                placeholder="user@example.com"
                value={memberEmail}
                onChange={(e) => setMemberEmail(e.target.value)}
                style={{ flex: 1 }}
                maxLength={254}
              />
              <button
                type="submit"
                className="sccap-btn sccap-btn-primary sccap-btn-sm"
                disabled={addMemberMutation.isPending || !memberEmail.trim()}
              >
                <Icon.Plus size={12} />{" "}
                {addMemberMutation.isPending ? "Adding…" : "Add member"}
              </button>
            </form>

            {activeGroup.members.length === 0 ? (
              <div
                className="inset"
                style={{
                  padding: 24,
                  textAlign: "center",
                  color: "var(--fg-subtle)",
                  fontSize: 13,
                }}
              >
                No members yet.
              </div>
            ) : (
              <div className="inset" style={{ padding: 0 }}>
                <table className="sccap-t">
                  <thead>
                    <tr>
                      <th>Email</th>
                      <th>Role</th>
                      <th style={{ width: 40 }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {activeGroup.members.map((m) => (
                      <tr key={m.user_id}>
                        <td
                          style={{
                            fontFamily: "var(--font-mono)",
                            color: "var(--fg)",
                          }}
                        >
                          {m.email}
                        </td>
                        <td>
                          <span className="chip">{m.role}</span>
                        </td>
                        <td>
                          <button
                            className="sccap-btn sccap-btn-icon sccap-btn-ghost"
                            aria-label="Remove member"
                            onClick={() =>
                              removeMemberMutation.mutate({
                                id: activeGroup.id,
                                userId: m.user_id,
                              })
                            }
                            disabled={removeMemberMutation.isPending}
                          >
                            <Icon.X size={12} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </Modal>
    </div>
  );
};

export default UserGroupsPage;
