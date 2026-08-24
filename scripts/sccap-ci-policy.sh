#!/bin/sh
# Submit an immutable source archive, poll persisted SCCAP policy, and fetch SARIF.
set -eu

if [ "${SCCAP_TRUSTED_CONTEXT:-false}" != "true" ]; then
  echo "SCCAP: untrusted/fork context; tenant-authenticated scan skipped."
  exit 0
fi

: "${SCCAP_BASE_URL:?SCCAP_BASE_URL is required}"
: "${SCCAP_TOKEN:?SCCAP_TOKEN is required only in trusted context}"
: "${SCCAP_PROVIDER:?SCCAP_PROVIDER is required}"
: "${SCCAP_COMMIT_SHA:?SCCAP_COMMIT_SHA is required}"
: "${SCCAP_REF:?SCCAP_REF is required}"
: "${SCCAP_REPOSITORY:?SCCAP_REPOSITORY is required}"
: "${SCCAP_PROJECT:?SCCAP_PROJECT is required}"
: "${SCCAP_FRAMEWORKS:?SCCAP_FRAMEWORKS is required}"
: "${SCCAP_ARCHIVE:?SCCAP_ARCHIVE is required}"

submission_json="$(curl --fail --silent --show-error \
  --request POST "${SCCAP_BASE_URL%/}/api/v1/integrations/ci/submissions" \
  --header "Authorization: Bearer ${SCCAP_TOKEN}" \
  --form-string "provider=${SCCAP_PROVIDER}" \
  --form-string "commit_sha=${SCCAP_COMMIT_SHA}" \
  --form-string "ref=${SCCAP_REF}" \
  --form-string "repository_slug=${SCCAP_REPOSITORY}" \
  --form-string "trusted_context=true" \
  --form-string "project_name=${SCCAP_PROJECT}" \
  --form-string "frameworks=${SCCAP_FRAMEWORKS}" \
  --form-string "scan_type=${SCCAP_SCAN_TYPE:-AUDIT}" \
  --form "archive_file=@${SCCAP_ARCHIVE}")" || exit 2

scan_id="$(printf '%s' "$submission_json" | jq --exit-status --raw-output '.scan_id')" || exit 2
echo "SCCAP scan accepted: ${scan_id}"

attempt=0
while [ "$attempt" -lt "${SCCAP_POLL_ATTEMPTS:-120}" ]; do
  policy_json="$(curl --fail --silent --show-error \
    "${SCCAP_BASE_URL%/}/api/v1/integrations/ci/scans/${scan_id}/policy" \
    --header "Authorization: Bearer ${SCCAP_TOKEN}")" || exit 2
  terminal="$(printf '%s' "$policy_json" | jq --exit-status --raw-output '.terminal')" || exit 2
  if [ "$terminal" = "true" ]; then
    outcome="$(printf '%s' "$policy_json" | jq --raw-output '.outcome // empty')" || exit 2
    report_url="$(printf '%s' "$policy_json" | jq --raw-output '.report_url // empty')" || exit 2
    if [ -z "$outcome" ]; then
      echo "SCCAP scan terminated without a persisted policy evaluation." >&2
      exit 2
    fi
    if [ -n "$report_url" ]; then
      curl --fail --silent --show-error \
        "${SCCAP_BASE_URL%/}${report_url}" \
        --header "Authorization: Bearer ${SCCAP_TOKEN}" \
        --output "${SCCAP_SARIF_OUTPUT:-sccap.sarif}" || exit 2
    fi
    if [ "$outcome" = "fail" ]; then
      echo "SCCAP persisted policy outcome: fail"
      exit 1
    fi
    if [ "$outcome" = "pass" ]; then
      echo "SCCAP persisted policy outcome: pass"
      exit 0
    fi
    echo "SCCAP returned an unknown persisted policy outcome." >&2
    exit 2
  fi
  attempt=$((attempt + 1))
  sleep "${SCCAP_POLL_SECONDS:-10}"
done

echo "SCCAP policy polling timed out; this is not a policy failure." >&2
exit 2
