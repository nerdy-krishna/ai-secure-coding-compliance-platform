#!/bin/bash
# Wrapper around the rabbitmq-server entrypoint that idempotently
# (re)creates the application user from RABBITMQ_DEFAULT_USER /
# RABBITMQ_DEFAULT_PASS. The image's built-in env-var seeding only
# fires on a fresh data volume, so a stale rabbitmq_data volume that
# predates these vars boots with zero users — the worker then crashes
# with ACCESS_REFUSED. This script closes that hole.
set -e

# Ensure the user exists with exactly the password the environment supplies.
# Creating-only-on-absence would keep a stale password after a rotation, and the
# consumer's URL (built from the same env var) would then be refused.
ensure_pentest_user() {
  # $1 user, $2 password, $3 configure, $4 write, $5 read (queue-scoped).
  local user="$1" pass="$2"
  [[ -n "$user" && -n "$pass" ]] || return 0
  if rabbitmqctl list_users -q --no-table-headers \
      | awk '{print $1}' | grep -qx "$user"; then
    rabbitmqctl change_password "$user" "$pass" >/dev/null
  else
    rabbitmqctl add_user "$user" "$pass" >/dev/null
  fi
  rabbitmqctl set_permissions -p / "$user" "$3" "$4" "$5"
}

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

  ensure_pentest_user \
    "${RABBITMQ_PENTEST_CONTROLLER_USER:-}" \
    "${RABBITMQ_PENTEST_CONTROLLER_PASS:-}" \
    '^pentest_controller_queue$' '^$' '^pentest_controller_queue$'

  ensure_pentest_user \
    "${RABBITMQ_PENTEST_TOOL_USER:-}" \
    "${RABBITMQ_PENTEST_TOOL_PASS:-}" \
    '^pentest_tool_queue_v1$' '^$' '^pentest_tool_queue_v1$'

  ensure_pentest_user \
    "${RABBITMQ_PENTEST_RUNNER_USER:-}" \
    "${RABBITMQ_PENTEST_RUNNER_PASS:-}" \
    '^pentest_execution_v3_queue$' '^$' '^pentest_execution_v3_queue$'

  ensure_pentest_user \
    "${RABBITMQ_PENTEST_VERIFICATION_USER:-}" \
    "${RABBITMQ_PENTEST_VERIFICATION_PASS:-}" \
    '^pentest_verification_queue_v1$' '^$' '^pentest_verification_queue_v1$'
}

ensure_user &
exec docker-entrypoint.sh rabbitmq-server
