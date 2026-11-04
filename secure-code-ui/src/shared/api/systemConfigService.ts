// secure-code-ui/src/shared/api/systemConfigService.ts
//
// DANGEROUS FUNCTIONALITY (V15.1.5): all writes here mutate runtime
// security configuration — CORS allowed origins, SMTP credentials, log
// level, and any encrypted secret stored in system_configurations. The
// process-local SystemConfigCache repopulates after a server restart, so
// callers MUST also nudge the backend to refresh the cache (see
// CLAUDE.md "core/config_cache.py"). Treat any new key written here as
// security-relevant; admin UI must confirm before save.
//
// System config values are free-form JSON documents — the backend stores
// them as JSONB and each key can hold anything from a boolean (cors_enabled)
// to a dict (smtp credentials, mode toggle, etc.).
import apiClient from "./apiClient";
import type { JsonValue } from "../types/api";

/**
 * SystemConfigValue is the free-form JSON value stored for each system
 * configuration key.  Well-known keys and their expected shapes (backend
 * Pydantic model is the authoritative source of truth — V2.1.1):
 *
 *   smtp                  – { host: string; port: number; username: string;
 *                             password: string; use_tls: boolean }
 *   cors_allowed_origins  – string[]
 *   log_level             – "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL"
 *   security.allowed_origins – string[]
 *
 * Any other key may carry any JSON-serialisable value.  If is_secret is
 * true the value must also have encrypted: true (see V2.1.2 / V2.2.3).
 */
export type SystemConfigValue = JsonValue;

interface SystemConfiguration {
    key: string;
    value: SystemConfigValue;
    description?: string;
    is_secret: boolean;
    encrypted: boolean;
    /** V02.3.4 — current row version; pass back as `expected_version` on update. */
    version?: number;
}

interface SystemConfigurationUpdate {
    value?: SystemConfigValue;
    description?: string;
    is_secret?: boolean;
    encrypted?: boolean;
    /** V02.3.4 — row version the client read; backend rejects with 409 if stale. */
    expected_version?: number;
}

// --- Input-validation helpers (V2.2.1) ---

/** Allow-list pattern for config keys: lowercase letter, then up to 63 lowercase
 *  alphanumeric / underscore / dot characters (dot for namespaced keys like
 *  "security.allowed_origins"). */
const CONFIG_KEY_RE = /^[a-z][a-z0-9_.]{0,63}$/;

function assertValidKey(key: string): void {
    if (!CONFIG_KEY_RE.test(key)) {
        throw new Error(`Invalid config key: "${key}". Keys must match ${CONFIG_KEY_RE}.`);
    }
}

/** Maximum size (bytes) of a serialised system-config payload (32 KiB). */
const MAX_PAYLOAD_BYTES = 32_768;

// --- Cross-field consistency guard (V2.1.2 / V2.2.3) ---

/**
 * assertConsistent – throws when the update payload contains combinations that
 * are logically forbidden:
 *   (a) is_secret === true && encrypted === false  (plaintext secret — V2.1.2)
 *   (b) is_secret === true with a non-string/non-object value (V2.2.3)
 */
function assertConsistent(data: SystemConfigurationUpdate): void {
    if (data.is_secret === true && data.encrypted === false) {
        throw new Error(
            "Invalid payload: is_secret=true requires encrypted=true. " +
            "Storing a secret in plaintext is not allowed (V2.1.2)."
        );
    }
    if (
        data.is_secret === true &&
        data.value !== undefined &&
        typeof data.value !== "string" &&
        (typeof data.value !== "object" || data.value === null)
    ) {
        throw new Error(
            "Invalid payload: when is_secret=true the value must be a string or object (V2.2.3)."
        );
    }
}

// --- Simple short-window memoisation for getAll (V2.4.1) ---

const GETALL_CACHE_TTL_MS = 5_000;
let _getAllCache: { data: SystemConfiguration[]; expiresAt: number } | null = null;

async function fetchAll(): Promise<SystemConfiguration[]> {
    const now = Date.now();
    if (_getAllCache && now < _getAllCache.expiresAt) {
        return _getAllCache.data;
    }
    const response = await apiClient.get<SystemConfiguration[]>("/admin/system-config/");
    _getAllCache = { data: response.data, expiresAt: now + GETALL_CACHE_TTL_MS };
    return response.data;
}

export const systemConfigService = {
    getAll: async (): Promise<SystemConfiguration[]> => {
        return fetchAll();
    },

    // V15.4.2: result may be stale by the time the caller acts on it — the UI
    // should fetch + write in a single optimistic transaction or accept that
    // another admin may have changed the value between this read and the
    // subsequent update/delete call.  When the backend exposes
    // GET /admin/system-config/{key}, swap to a direct apiClient.get call so
    // the read is atomic.
    getByKey: async (key: string): Promise<SystemConfiguration> => {
        // V2.2.1 — validate key before it touches the network
        assertValidKey(key);
        const all = await fetchAll();
        const found = all.find(c => c.key === key);
        if (!found) {
            throw new Error(`Configuration key ${key} not found`);
        }
        return found;
    },

    /**
     * update — persist a partial update for the given config key.
     *
     * WARNING (V15.1.5): this may mutate CORS origins, SMTP credentials or
     * encrypted secrets.  Callers must present a confirmation dialog before
     * invoking for security-critical keys.
     */
    update: async (key: string, data: SystemConfigurationUpdate): Promise<SystemConfiguration> => {
        // V2.2.1 — allow-list key before URL interpolation
        assertValidKey(key);
        // V2.1.2 / V2.2.3 — cross-field consistency check
        assertConsistent(data);
        // V15.3.3 — build an explicit payload (no mass-assignment)
        const payload: SystemConfigurationUpdate = {};
        if (data.value !== undefined) payload.value = data.value;
        if (data.description !== undefined) payload.description = data.description;
        if (data.is_secret !== undefined) payload.is_secret = data.is_secret;
        if (data.encrypted !== undefined) payload.encrypted = data.encrypted;
        // V02.3.4 — pass the row version the caller read so the backend can
        // reject stale writes (409 + current_version in the body).
        if (data.expected_version !== undefined) {
            payload.expected_version = data.expected_version;
        }
        // V2.2.1 — size-cap the serialised body
        if (JSON.stringify(payload).length > MAX_PAYLOAD_BYTES) {
            throw new Error(`System config payload exceeds the ${MAX_PAYLOAD_BYTES}-byte limit (V2.2.1).`);
        }
        // V1.2.2 — percent-encode key so reserved URL characters don't alter path semantics
        const response = await apiClient.put<SystemConfiguration>(
            `/admin/system-config/${encodeURIComponent(key)}`,
            payload
        );
        // Invalidate the short-window cache so the next getAll/getByKey is fresh
        _getAllCache = null;
        return response.data;
    },

    delete: async (key: string): Promise<void> => {
        // V2.2.1 — allow-list key before URL interpolation
        assertValidKey(key);
        // V1.2.2 — percent-encode key
        await apiClient.delete(`/admin/system-config/${encodeURIComponent(key)}`);
        // Invalidate cache
        _getAllCache = null;
    }
};

/**
 * The running build. `display` changes on every successful update because the
 * commit changes, which is how an operator confirms a deploy actually landed.
 */
export interface BuildVersion {
  version: string;
  commit: string;
  commit_short: string;
  display: string;
  versioned: boolean;
  built_at: string | null;
  environment: string;
  migration_head: string | null;
}

export async function getBuildVersion(): Promise<BuildVersion> {
  const { data } = await apiClient.get<BuildVersion>("/system/version");
  return data;
}
