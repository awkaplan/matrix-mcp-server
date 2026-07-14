import { MatrixClient } from "matrix-js-sdk";
import { restoreKeyBackupWithRecoveryKey } from "./client.js";

export interface EncryptionStatus {
  cryptoInitialized: boolean;
  deviceId: string | null;
  backupExists: boolean;
  hasBackupKeyLoaded: boolean;
  restoreAttempted: boolean;
  restoreOutcome?: "restored" | "no-backup" | "failed";
  restoreImported?: number;
  restoreTotal?: number;
  restoreError?: string;
}

/**
 * Reports the current state of end-to-end encryption for this session,
 * directly through the tool response rather than requiring server log
 * access. If a server-side key backup exists but its decryption key isn't
 * loaded yet and a recovery key is supplied, attempts to restore it right
 * here and reports exactly what happened -- restoring at client-creation
 * time only ever logged its outcome to console, which proved impractical
 * to read back in practice (see restoreKeyBackupWithRecoveryKey's comment).
 */
export async function getEncryptionStatus(
  client: MatrixClient,
  recoveryKey?: string
): Promise<EncryptionStatus> {
  const deviceId = client.getDeviceId();
  const crypto = client.getCrypto();
  if (!crypto) {
    return {
      cryptoInitialized: false,
      deviceId,
      backupExists: false,
      hasBackupKeyLoaded: false,
      restoreAttempted: false,
    };
  }

  const backupInfo = await crypto.getKeyBackupInfo();
  const backupExists = !!backupInfo?.version;
  const hasBackupKeyLoaded = backupExists
    ? (await crypto.getSessionBackupPrivateKey()) !== null
    : false;

  const status: EncryptionStatus = {
    cryptoInitialized: true,
    deviceId,
    backupExists,
    hasBackupKeyLoaded,
    restoreAttempted: false,
  };

  if (backupExists && !hasBackupKeyLoaded && recoveryKey) {
    status.restoreAttempted = true;
    const result = await restoreKeyBackupWithRecoveryKey(crypto, recoveryKey);
    status.restoreOutcome = result.outcome;
    status.restoreImported = result.imported;
    status.restoreTotal = result.total;
    status.restoreError = result.error;
    if (result.outcome === "restored") {
      status.hasBackupKeyLoaded = true;
    }
  }

  return status;
}
