import { MatrixClient } from "matrix-js-sdk";
import {
  VerificationRequest,
  Verifier,
  VerifierEvent,
  VerificationPhase,
  ShowSasCallbacks,
} from "matrix-js-sdk/lib/crypto-api/verification.js";

/**
 * State for a verification handshake in progress, spanning the gap between
 * separate start-device-verification calls (a human needs real time to
 * notice a push notification and respond) and the eventual
 * confirm-device-verification call -- each its own MCP request against the
 * same cached MatrixClient.
 */
interface PendingVerification {
  request: VerificationRequest;
  requestedAt: number;
  verifier?: Verifier;
  /**
   * Set once we've called request.startVerification() ourselves, so the
   * poll loop below never calls it more than once. Without this guard it
   * fired on every 300ms tick for as long as phase stayed Ready (since the
   * "grace period elapsed" condition stays true forever once past the
   * threshold), spamming repeated m.key.verification.start events --
   * confirmed experimentally to leave the exchange never converging on our
   * own side even though the other device could still complete its half.
   */
  startAttempted?: boolean;
  /**
   * Set exactly once, the first time a verifier is seen -- never re-attach
   * a fresh listener on a later call. ShowSas only fires once, and it can
   * land in the background between two separate start-device-verification
   * calls; a later call re-registering with .once() would miss it forever
   * and the tool would report "still waiting" indefinitely even though
   * verification already succeeded on the other side (confirmed
   * experimentally). Every call after the first just awaits this same
   * promise instead.
   */
  showSasPromise?: Promise<ShowSasCallbacks>;
  sasEvent?: ShowSasCallbacks;
  verifyPromise?: Promise<void>;
}

/**
 * Key: ${userId}:${homeserverUrl}, matching clientCache.ts's cache key --
 * a pending verification only makes sense against the same cached client.
 */
const pendingVerifications = new Map<string, PendingVerification>();

/**
 * How long to wait, while a request is still stuck at phase Requested (the
 * other device hasn't even accepted yet), before assuming it was silently
 * dropped and sending a fresh one. Confirmed experimentally: rust-crypto
 * drops an incoming verification request outright (no retry of its own) if
 * the receiving device hasn't yet learned about this device via
 * /keys/query -- a request stuck like this will NEVER progress no matter
 * how long you wait, so this can stay fairly short.
 */
const EARLY_STALE_MS = 25000;

/**
 * How long to wait once a request has progressed past Requested (the other
 * device has visibly engaged -- accepted, or further) before giving up and
 * starting over. Much longer than EARLY_STALE_MS: at this point a human is
 * plausibly mid-interaction (comparing emoji, etc.), and the only known
 * cause of a post-Ready stall (neither side starting the SAS method) is
 * already handled by the proactive startVerification() call below, so this
 * threshold should rarely if ever actually be hit.
 */
const STALE_REQUEST_MS = 3 * 60 * 1000;

/** How long a single tool call blocks before returning "still waiting". */
const PER_CALL_WAIT_MS = 15000;

/**
 * How long to give the *other* device a chance to start the SAS exchange
 * itself, once it has accepted (phase Ready), before we start it. Some
 * clients auto-start on accept; others wait for the request's initiator
 * (us) to pick a method. If neither side ever takes the initiative both
 * just wait on each other forever -- confirmed experimentally against
 * FluffyChat, which does the latter.
 */
const READY_GRACE_MS = 3000;

function getCacheKey(userId: string, homeserverUrl: string): string {
  return `${userId}:${homeserverUrl}`;
}

function formatEmoji(sasEvent: ShowSasCallbacks): string {
  return (sasEvent.sas.emoji ?? [])
    .map(([emoji, name]) => `${emoji} (${name})`)
    .join("  ");
}

/**
 * Advances a pending verification as far as possible within one bounded
 * call: proactively starting SAS if the other side accepted but hasn't
 * started it themselves, then waiting for the resulting emoji.
 */
async function pumpVerification(
  pending: PendingVerification
): Promise<ShowSasCallbacks | null> {
  const deadline = Date.now() + PER_CALL_WAIT_MS;
  let readySince: number | null = null;

  if (!pending.verifier) {
    while (Date.now() < deadline) {
      if (pending.request.verifier) {
        pending.verifier = pending.request.verifier;
        break;
      }
      if (pending.request.phase === VerificationPhase.Ready) {
        readySince ??= Date.now();
        if (!pending.startAttempted && Date.now() - readySince > READY_GRACE_MS) {
          pending.startAttempted = true;
          try {
            await pending.request.startVerification("m.sas.v1");
          } catch {
            // May race with the other side starting it at the same moment;
            // request.verifier will already be set in that case regardless.
          }
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  }

  if (!pending.verifier) {
    return null;
  }

  // Attach the ShowSas listener and kick off verify() exactly once, the
  // moment a verifier first appears -- see the showSasPromise field comment
  // for why this must never happen more than once per verifier.
  if (!pending.showSasPromise) {
    // The SAS calculation is a one-shot: RustSASVerifier computes and emits
    // ShowSas exactly once, and it can complete entirely in the background
    // during the startVerification() await above -- before this function
    // ever gets a chance to attach a .once() listener. Confirmed
    // experimentally: getShowSasCallbacks() already has the (correct,
    // matching) data by the time we get here in that case, and a fresh
    // .once() listener would simply never fire since the single emission
    // already happened. Check for that first; only fall back to listening
    // for the live event if it genuinely hasn't fired yet.
    const already = pending.verifier.getShowSasCallbacks();
    pending.showSasPromise = already
      ? Promise.resolve(already)
      : new Promise<ShowSasCallbacks>((resolve) => {
          pending.verifier!.once(VerifierEvent.ShowSas, resolve);
        });
    const verifyPromise = pending.verifier.verify();
    // Surface (but don't rethrow past this function) verify() rejections
    // that happen before confirm-device-verification ever gets a chance to
    // await it, so they don't become an unhandled rejection.
    verifyPromise.catch(() => {});
    pending.verifyPromise = verifyPromise;
  }

  const remaining = deadline - Date.now();
  const sasEvent = await Promise.race([
    pending.showSasPromise,
    new Promise<null>((resolve) =>
      setTimeout(() => resolve(null), Math.max(remaining, 0))
    ),
  ]);

  return sasEvent;
}

/**
 * Starts (or resumes) an interactive self-verification with the user's own
 * other devices, and returns the SAS emoji to compare once the other side
 * has accepted and a verification method has been chosen.
 *
 * Safe to call repeatedly while waiting on a human to respond on their
 * other device -- resumes the same underlying request rather than spamming
 * new ones, and only gives up on a request (cancelling and starting a
 * fresh one) after STALE_REQUEST_MS of no progress at all.
 */
export async function startDeviceVerification(
  client: MatrixClient,
  userId: string,
  homeserverUrl: string
): Promise<{ emoji?: string; waiting?: boolean }> {
  const key = getCacheKey(userId, homeserverUrl);
  const crypto = client.getCrypto();
  if (!crypto) {
    throw new Error(
      "End-to-end encryption is not initialized for this session."
    );
  }

  let pending = pendingVerifications.get(key);

  if (pending?.sasEvent) {
    return { emoji: formatEmoji(pending.sasEvent) };
  }

  const staleThreshold =
    pending && pending.request.phase < VerificationPhase.Ready
      ? EARLY_STALE_MS
      : STALE_REQUEST_MS;
  const isStale =
    pending &&
    !pending.verifier &&
    Date.now() - pending.requestedAt > staleThreshold;

  if (!pending || isStale) {
    if (isStale) {
      try {
        await pending!.request.cancel();
      } catch {
        // best-effort; proceed to send a fresh request regardless
      }
    }
    const request = await crypto.requestOwnUserVerification();
    pending = { request, requestedAt: Date.now() };
    pendingVerifications.set(key, pending);
  }

  const sasEvent = await pumpVerification(pending);
  if (!sasEvent) {
    return { waiting: true };
  }

  pending.sasEvent = sasEvent;
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
  if (!pending || !pending.sasEvent || !pending.verifyPromise) {
    throw new Error(
      "No verification is ready to confirm. Call start-device-verification first and wait for it to return emoji."
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
