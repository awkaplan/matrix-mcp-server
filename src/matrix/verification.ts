import { MatrixClient } from "matrix-js-sdk";
import {
  VerificationRequest,
  Verifier,
  VerifierEvent,
  ShowSasCallbacks,
} from "matrix-js-sdk/lib/crypto-api/verification.js";

/**
 * State for a verification handshake in progress, spanning the gap between
 * the start-device-verification and confirm-device-verification tool calls
 * (each a separate MCP request against the same cached MatrixClient).
 */
interface PendingVerification {
  request: VerificationRequest;
  sasEvent: ShowSasCallbacks;
  verifyPromise: Promise<void>;
}

/**
 * Key: ${userId}:${homeserverUrl}, matching clientCache.ts's cache key --
 * a pending verification only makes sense against the same cached client.
 */
const pendingVerifications = new Map<string, PendingVerification>();

function getCacheKey(userId: string, homeserverUrl: string): string {
  return `${userId}:${homeserverUrl}`;
}

function formatEmoji(sasEvent: ShowSasCallbacks): string {
  return (sasEvent.sas.emoji ?? [])
    .map(([emoji, name]) => `${emoji} (${name})`)
    .join("  ");
}

/**
 * Waits for a verifier to appear on a self-verification request, i.e. for
 * one of the user's other devices to respond with an m.key.verification.start.
 *
 * Rust-crypto silently drops an incoming verification request if the
 * receiving device hasn't yet learned about this device via /keys/query --
 * confirmed experimentally, with no retry on its side. If nothing happens
 * within the first window, cancel and resend once: by the second attempt
 * the other device's own sync loop has typically caught up.
 */
async function waitForVerifier(
  crypto: NonNullable<ReturnType<MatrixClient["getCrypto"]>>,
  initialRequest: VerificationRequest,
  attemptTimeoutMs: number = 20000
): Promise<{ request: VerificationRequest; verifier: Verifier }> {
  let request = initialRequest;

  for (let attempt = 0; attempt < 2; attempt++) {
    const deadline = Date.now() + attemptTimeoutMs;
    while (Date.now() < deadline) {
      if (request.verifier) {
        return { request, verifier: request.verifier };
      }
      await new Promise((resolve) => setTimeout(resolve, 300));
    }

    if (attempt === 0) {
      try {
        await request.cancel();
      } catch {
        // best-effort; fall through to resend regardless
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
      request = await crypto.requestOwnUserVerification();
    }
  }

  throw new Error(
    `No response from any other device. Make sure another Matrix client (e.g. Element or Cinny) is open and signed in, then try again. (phase=${request.phase})`
  );
}

/**
 * Starts (or resumes) an interactive self-verification with the user's own
 * other devices, and returns the SAS emoji to compare once the other side
 * has accepted and chosen the emoji method.
 *
 * Safe to call again if a previous call is still pending -- reuses the
 * existing sasEvent instead of starting a second concurrent verification.
 */
export async function startDeviceVerification(
  client: MatrixClient,
  userId: string,
  homeserverUrl: string
): Promise<{ emoji: string }> {
  const key = getCacheKey(userId, homeserverUrl);
  const existing = pendingVerifications.get(key);
  if (existing) {
    return { emoji: formatEmoji(existing.sasEvent) };
  }

  const crypto = client.getCrypto();
  if (!crypto) {
    throw new Error(
      "End-to-end encryption is not initialized for this session."
    );
  }

  const initialRequest = await crypto.requestOwnUserVerification();
  const { request, verifier } = await waitForVerifier(crypto, initialRequest);

  const showSasPromise = new Promise<ShowSasCallbacks>((resolve) => {
    verifier.once(VerifierEvent.ShowSas, resolve);
  });
  const verifyPromise = verifier.verify();
  // Surface (but don't rethrow past this function) verify() rejections that
  // happen before confirm-device-verification ever gets a chance to await
  // it, so they don't become an unhandled rejection.
  verifyPromise.catch(() => {});

  const sasEvent = await showSasPromise;
  pendingVerifications.set(key, { request, sasEvent, verifyPromise });

  return { emoji: formatEmoji(sasEvent) };
}

export interface VerificationResult {
  verified: boolean;
  /**
   * "restored": key backup existed and was successfully pulled in.
   * "pending": key backup exists but its decryption key hadn't arrived via
   *   gossip yet -- the SDK's background downloader will keep retrying.
   * "none": no server-side key backup exists for this account.
   */
  backupStatus: "restored" | "pending" | "none";
  backupRestored?: { imported: number; total: number };
}

/**
 * Confirms or rejects the emoji comparison for a pending verification
 * started by startDeviceVerification(), then attempts to pull the account's
 * key backup (received via secret gossip once verification completes, with
 * no manual recovery key needed) so encrypted-room history can decrypt too.
 */
export async function confirmDeviceVerification(
  client: MatrixClient,
  userId: string,
  homeserverUrl: string,
  matches: boolean
): Promise<VerificationResult> {
  const key = getCacheKey(userId, homeserverUrl);
  const pending = pendingVerifications.get(key);
  if (!pending) {
    throw new Error(
      "No verification is in progress. Call start-device-verification first."
    );
  }
  pendingVerifications.delete(key);

  if (!matches) {
    pending.sasEvent.mismatch();
    return { verified: false, backupStatus: "none" };
  }

  await pending.sasEvent.confirm();
  await pending.verifyPromise;

  const result: VerificationResult = { verified: true, backupStatus: "none" };

  const crypto = client.getCrypto();
  if (crypto) {
    try {
      const backupInfo = await crypto.getKeyBackupInfo();
      if (backupInfo?.version) {
        // No loadSessionBackupPrivateKeyFromSecretStorage() call needed: the
        // backup decryption key arrives automatically via m.secret.send
        // gossip shortly after verification completes -- but "shortly" is a
        // separate async to-device round trip, not instant. Confirmed
        // experimentally: calling restoreKeyBackup() immediately after
        // verifyPromise resolves can race ahead of the gossip and fail with
        // "No decryption key found in crypto store" even though the key
        // arrives correctly a moment later.
        const deadline = Date.now() + 10000;
        let hasKey = false;
        while (Date.now() < deadline) {
          hasKey = (await crypto.getSessionBackupPrivateKey()) !== null;
          if (hasKey) break;
          await new Promise((resolve) => setTimeout(resolve, 500));
        }

        if (hasKey) {
          const restoreResult = await crypto.restoreKeyBackup();
          result.backupStatus = "restored";
          result.backupRestored = {
            imported: restoreResult.imported,
            total: restoreResult.total,
          };
        } else {
          // Backup exists and the key is presumably still in flight via
          // gossip; the SDK's own background downloader will keep trying
          // and pick it up shortly without any further action needed here.
          result.backupStatus = "pending";
        }
      }
    } catch (error: any) {
      console.warn(`Key backup restore after verification failed: ${error.message}`);
      result.backupStatus = "pending";
    }
  }

  return result;
}
