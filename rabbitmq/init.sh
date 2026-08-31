#!/bin/bash
# Wrapper around the rabbitmq-server entrypoint that idempotently
# (re)creates the application user from RABBITMQ_DEFAULT_USER /
# RABBITMQ_DEFAULT_PASS. The image's built-in env-var seeding only
# fires on a fresh data volume, so a stale rabbitmq_data volume that
# predates these vars boots with zero users — the worker then crashes
# with ACCESS_REFUSED. This script closes that hole.
set -e

ensure_user() {
  until rabbitmqctl status >/dev/null 2>&1; do sleep 2; done
  local user="${RABBITMQ_DEFAULT_USER:?RABBITMQ_DEFAULT_USER unset}"
  local pass="${RABBITMQ_DEFAULT_PASS:?RABBITMQ_DEFAULT_PASS unset}"
  if ! rabbitmqctl list_users -q --no-table-headers \
      | awk '{print $1}' | grep -qx "$user"; then
    echo "rabbitmq-init: creating user '$user'"
    rabbitmqctl add_user "$user" "$pass"
    rabbitmqctl set_user_tags "$user" administrator
  fi
  rabbitmqctl set_permissions -p / "$user" '.*' '.*' '.*'

  local controller_user="${RABBITMQ_PENTEST_CONTROLLER_USER:-}"
  local controller_pass="${RABBITMQ_PENTEST_CONTROLLER_PASS:-}"
  if [[ -n "$controller_user" && -n "$controller_pass" ]]; then
    if ! rabbitmqctl list_users -q --no-table-headers \
        | awk '{print $1}' | grep -qx "$controller_user"; then
      echo "rabbitmq-init: creating bounded controller user '$controller_user'"
      rabbitmqctl add_user "$controller_user" "$controller_pass"
    fi
    rabbitmqctl set_permissions -p / "$controller_user" \
      '^pentest_controller_queue$' '^$' '^pentest_controller_queue$'
  fi

  local tool_user="${RABBITMQ_PENTEST_TOOL_USER:-}"
  local tool_pass="${RABBITMQ_PENTEST_TOOL_PASS:-}"
  if [[ -n "$tool_user" && -n "$tool_pass" ]]; then
    if ! rabbitmqctl list_users -q --no-table-headers \
        | awk '{print $1}' | grep -qx "$tool_user"; then
      echo "rabbitmq-init: creating bounded tool-worker user '$tool_user'"
      rabbitmqctl add_user "$tool_user" "$tool_pass"
    fi
    rabbitmqctl set_permissions -p / "$tool_user" \
      '^pentest_tool_queue_v1$' '^$' '^pentest_tool_queue_v1$'
  fi

  local verifier_user="${RABBITMQ_PENTEST_VERIFICATION_USER:-}"
  local verifier_pass="${RABBITMQ_PENTEST_VERIFICATION_PASS:-}"
  if [[ -n "$verifier_user" && -n "$verifier_pass" ]]; then
    if ! rabbitmqctl list_users -q --no-table-headers \
        | awk '{print $1}' | grep -qx "$verifier_user"; then
      echo "rabbitmq-init: creating bounded verification user '$verifier_user'"
      rabbitmqctl add_user "$verifier_user" "$verifier_pass"
    fi
    rabbitmqctl set_permissions -p / "$verifier_user" \
      '^pentest_verification_queue_v1$' '^$' '^pentest_verification_queue_v1$'
  fi
}

ensure_user &
exec docker-entrypoint.sh rabbitmq-server
