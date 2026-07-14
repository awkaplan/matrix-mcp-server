import * as sdk from "matrix-js-sdk";
import { MatrixClient, ClientEvent } from "matrix-js-sdk";
import { decodeRecoveryKey } from "matrix-js-sdk/lib/crypto-api/recovery-key.js";
import https from "https";
import fetch from "node-fetch";
import { exchangeToken, TokenExchangeConfig } from "../auth/tokenExchange.js";
import { getCachedClient, cacheClient, removeCachedClient } from "./clientCache.js";
import { watchForIncomingVerification } from "./verification.js";

export interface RecoveryKeyRestoreResult {
  outcome: "restored" | "no-backup" | "failed";
  imported?: number;
  total?: number;
  error?: string;
}

/**
 * Restores server-side key backup using a Secure Backup recovery key.
 * Shared between createMatrixClient() (attempts this automatically at cold
 * start if a recovery key is configured) and the get-encryption-status
 * tool (attempts it on demand and reports exactly what happened) --
 * factored out because the only way to previously observe the outcome of
 * this was console.log/warn output buried in server logs, which turned
 * out to be impractical to actually read back: this account generates
 * thousands of log lines per cold client creation from historical
 * decrypt-failure spam alone, easily exceeding docker log tooling's tail
 * limits before reaching the lines that would show whether restore
 * actually worked.
 */
export async function restoreKeyBackupWithRecoveryKey(
  crypto: NonNullable<ReturnType<MatrixClient["getCrypto"]>>,
  recoveryKey: string
): Promise<RecoveryKeyRestoreResult> {
  try {
    const backupInfo = await crypto.getKeyBackupInfo();
    if (!backupInfo?.version) {
      return { outcome: "no-backup" };
    }
    const privateKey = decodeRecoveryKey(recoveryKey);
    await crypto.storeSessionBackupPrivateKey(privateKey, backupInfo.version);
    // Establishes trust for the backup (our locally-stored key now matches
    // it) and activates the SDK's per-session downloader's retry path --
    // without this, restoreKeyBackup() below still reports success with
    // the right imported/total counts, but any event whose decryption was
    // already attempted-and-failed before the key became available (the
    // common case for this function's second caller: a client that was
    // already cached and synced before a recovery key was ever supplied)
    // never actually gets re-decrypted. Confirmed experimentally: the
    // identical restore sequence without this call reports success but
    // the message stays permanently stuck as "Unable to decrypt".
    await crypto.checkKeyBackupAndEnable();
    const result = await crypto.restoreKeyBackup();
    return { outcome: "restored", imported: result.imported, total: result.total };
  } catch (error: any) {
    return { outcome: "failed", error: error.message };
  }
}

/**
 * Configuration for Matrix client creation
 */
export interface MatrixClientConfig {
  homeserverUrl: string;
  userId: string;
  accessToken: string;
  enableOAuth: boolean;
  tokenExchangeConfig?: TokenExchangeConfig;
  enableTokenExchange: boolean;
  /**
   * Account's Secure Backup recovery key (the "EsUx ...." string), used to
   * restore server-side key backup so this ephemeral device can decrypt
   * encrypted-room history from before it existed. Optional -- without it,
   * crypto still initializes and can decrypt anything shared going forward,
   * but historical messages in encrypted rooms stay opaque.
   */
  recoveryKey?: string;
}

/**
 * Creates and initializes a Matrix client instance, using cache when possible
 *
 * @param config - Matrix client configuration
 * @returns Promise<MatrixClient> - Initialized Matrix client
 */
export async function createMatrixClient(
  config: MatrixClientConfig
): Promise<MatrixClient> {
  const {
    homeserverUrl,
    userId,
    accessToken,
    enableOAuth,
    tokenExchangeConfig,
    enableTokenExchange,
    recoveryKey,
  } = config;

  if (!homeserverUrl) {
    throw new Error("Homeserver URL is required to create a Matrix client.");
  }
  if (!userId) {
    throw new Error("User ID is required to create a Matrix client.");
  }

  // Check for cached client first
  const cachedClient = getCachedClient(userId, homeserverUrl);
  if (cachedClient) {
    return cachedClient;
  }

  // No cached client, create a new one
  let matrixAccessToken: string;

  if (enableOAuth && enableTokenExchange) {
    if (!accessToken) {
      throw new Error("Access token is required for OAuth token exchange.");
    }
    if (!tokenExchangeConfig) {
      throw new Error(
        "Token exchange configuration is required for OAuth mode."
      );
    }
    matrixAccessToken = await exchangeToken(tokenExchangeConfig, accessToken);
  } else {
    // In non-OAuth mode, expect a direct Matrix access token
    matrixAccessToken = accessToken;
  }

  const client = sdk.createClient({
    baseUrl: homeserverUrl,
    userId,
    fetchFn: async (input: any, init?: any) => {
      const agent = new https.Agent({ rejectUnauthorized: false });
      return fetch(input, { ...(init || {}), agent }) as any;
    },
  });

  try {
    if (enableOAuth && matrixAccessToken && enableTokenExchange) {
      // OAuth mode: use token exchange result to login
      const matrixLoginResponse = await client.loginRequest({
        type: "org.matrix.login.jwt",
        token: matrixAccessToken,
      });
      client.setAccessToken(matrixLoginResponse.access_token);
      // loginRequest() hands back the device_id assigned to this session --
      // rust-crypto below requires it to already be set on the client.
      client.deviceId = matrixLoginResponse.device_id ?? null;
    } else if (matrixAccessToken) {
      // Non-OAuth mode: use provided Matrix access token directly
      client.setAccessToken(matrixAccessToken);
      // Direct-token mode never runs a real login, so the SDK has no way to
      // know its own device_id -- ask the homeserver. Needed because
      // rust-crypto keys everything (Olm/Megolm sessions, key backup)
      // per-device and refuses to initialize without one.
      try {
        const whoami = await client.whoami();
        client.deviceId = whoami.device_id ?? null;
      } catch (error: any) {
        console.warn(
          `Could not determine device ID via whoami(); encrypted rooms will not decrypt: ${error.message}`
        );
      }
    } else {
      throw new Error("No valid access token available for Matrix client.");
    }

    // End-to-end encryption: without this, every event in an encrypted room
    // stays typed m.room.encrypted and is invisible to the message-reading
    // tools. Must run before startClient() so incoming/historical events get
    // decrypted as the timeline is populated during the initial sync.
    if (client.getDeviceId()) {
      try {
        // In-memory crypto store (no IndexedDB in Node) -- scoped to this
        // cached client's process lifetime (see clientCache.ts's 15-minute
        // idle TTL), rebuilt via key backup restore below on each cold start
        // rather than persisted to disk.
        await client.initRustCrypto({ useIndexedDB: false });

        // Some clients (confirmed: FluffyChat) never surface any UI for an
        // incoming self-verification request sent via
        // requestOwnUserVerification() -- the only reliable path with them
        // is to accept a request THEY initiate instead. Register before
        // startClient() so nothing arriving during the first sync is missed.
        watchForIncomingVerification(client, userId, homeserverUrl);

        if (recoveryKey) {
          const crypto = client.getCrypto();
          if (crypto) {
            const restoreResult = await restoreKeyBackupWithRecoveryKey(
              crypto,
              recoveryKey
            );
            if (restoreResult.outcome === "restored") {
              console.log(
                `Restored ${restoreResult.imported}/${restoreResult.total} keys from server-side key backup`
              );
            } else if (restoreResult.outcome === "no-backup") {
              console.warn(
                "No server-side key backup found; encrypted messages sent before this device existed will not decrypt"
              );
            } else {
              console.warn(
                `Key backup restore failed; encrypted messages may not decrypt: ${restoreResult.error}`
              );
            }
          }
        }
      } catch (error: any) {
        console.warn(
          `Failed to initialize end-to-end encryption; encrypted messages will not decrypt: ${error.message}`
        );
      }
    } else {
      console.warn(
        "No device ID available; encrypted rooms will not decrypt"
      );
    }

    await client.startClient({ initialSyncLimit: 100 });

    // Wait for the initial sync to complete
    await new Promise<void>((resolve, reject) => {
      client.once(ClientEvent.Sync, (state) => {
        if (state === "PREPARED") resolve();
        else reject(new Error(`Sync failed with state: ${state}`));
      });
    });

    // Cache the successfully created and synced client
    cacheClient(client, userId, homeserverUrl);
    
    return client;
  } catch (error) {
    // If client creation failed, make sure to stop the client and don't cache it
    try {
      client.stopClient();
    } catch (stopError) {
      console.warn("Error stopping failed client:", stopError);
    }
    throw error;
  }
}

/**
 * Safely stops a Matrix client and cleans up resources
 * Note: This function is now deprecated since clients are cached and managed automatically.
 * Clients should not be manually stopped as they may be reused by other operations.
 *
 * @param client - Matrix client to stop
 * @deprecated Use cached clients instead, they are managed automatically
 */
export function stopMatrixClient(_client: MatrixClient): void {
  // For now, do nothing - clients are managed by the cache
  // In the future, we may want to remove this function entirely
  console.warn("stopMatrixClient called - clients are now cached and should not be manually stopped");
}

/**
 * Remove a client from cache and stop it (for error recovery)
 *
 * @param userId - Matrix user ID  
 * @param homeserverUrl - Matrix homeserver URL
 */
export function removeClientFromCache(userId: string, homeserverUrl: string): void {
  removeCachedClient(userId, homeserverUrl);
}
