import bs58 from "bs58";
import { Buffer } from "buffer";
import {
  clusterApiUrl,
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  PublicKey,
  SendTransactionError,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import type { Commitment } from "@solana/web3.js";
import {
  SignerExecutionScheme,
  SLOT_HASHES_SYSVAR_ID,
  buildExecuteInstructions,
  buildExecuteInstructionsSessioned,
  buildInitializePasskeyAccount,
  buildPrecompileMessage,
  buildRefreshSessionKey,
  createExecuteInstructionsChallenge,
  createInitializePasskeyChallenge,
  createRefreshSessionKeyChallenge,
  createSecp256r1Instruction,
  deriveExecutionAccount,
  truncateSlotForValidator,
} from "external-signature-ts-sdk";
import type { WebAuthnData } from "external-signature-ts-sdk";
import {
  credentialIdToString,
  fromBase64Url,
  parseAuthenticationCredential,
  parseRegistrationCredential,
  toBase64Url,
} from "external-signature-ts-sdk/webauthn";

const MEMO_PROGRAM_ID = new PublicKey(
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
);
const STORAGE_PASSKEY = "external-signature-demo:passkey";
const STORAGE_SESSION = "external-signature-demo:session";
const RPC_URL = import.meta.env.VITE_RPC_URL || clusterApiUrl("devnet");
const PAYMASTER_SECRET = import.meta.env.VITE_PAYMASTER_SECRET_KEY || "";
const CHALLENGE_COMMITMENT: Commitment = "finalized";
const TRANSACTION_COMMITMENT: Commitment = "confirmed";
const SESSION_DURATION_SECONDS = 15 * 60;
const SESSION_SIGNER_MIN_LAMPORTS = 0.005 * LAMPORTS_PER_SOL;
const SESSION_SIGNER_TOPUP_LAMPORTS = 0.01 * LAMPORTS_PER_SOL;
const PASSKEY_FUNDING_LAMPORTS = 0.01 * LAMPORTS_PER_SOL;
const PASSKEY_TRANSFER_LAMPORTS = 100_000;

type StoredPasskey = {
  passkeyAccount: string;
  credentialId: string;
  compressedPublicKey: string;
  rpId: string;
};

type StoredSession = {
  sessionSignerSecretKey: string;
  sessionSignerPubkey: string;
  expiresAtUnixSeconds: number;
};

const connection = new Connection(RPC_URL, TRANSACTION_COMMITMENT);
const paymaster = loadPaymasterFromEnv();
const rpId = getRpId();
const webauthnRp = getWebauthnRp();

const stateEl = document.querySelector<HTMLDListElement>("#state")!;
const logEl = document.querySelector<HTMLPreElement>("#log")!;
const registerButton = document.querySelector<HTMLButtonElement>("#register")!;
const memoButton = document.querySelector<HTMLButtonElement>("#memo")!;
const sessionInitButton =
  document.querySelector<HTMLButtonElement>("#session-init")!;
const sessionedMemoButton =
  document.querySelector<HTMLButtonElement>("#memo-sessioned")!;
const fundPasskeyButton =
  document.querySelector<HTMLButtonElement>("#fund-passkey")!;
const transferPasskeyButton =
  document.querySelector<HTMLButtonElement>("#transfer-passkey")!;
const resetButton = document.querySelector<HTMLButtonElement>("#reset")!;

if (
  !stateEl ||
  !logEl ||
  !registerButton ||
  !memoButton ||
  !sessionInitButton ||
  !sessionedMemoButton ||
  !fundPasskeyButton ||
  !transferPasskeyButton ||
  !resetButton
) {
  throw new Error("demo UI failed to initialize");
}

registerButton.addEventListener("click", () => void initializePasskey());
memoButton.addEventListener("click", () => void sendMemoWithPasskey());
sessionInitButton.addEventListener("click", () => void initializeSessionKey());
sessionedMemoButton.addEventListener(
  "click",
  () => void sendMemoWithSessionKey(),
);
fundPasskeyButton.addEventListener(
  "click",
  () => void fundPasskeyForTransferTest(),
);
transferPasskeyButton.addEventListener(
  "click",
  () => void sendTransferWithPasskey(),
);
resetButton.addEventListener("click", resetLocalState);

renderState();
log(`RPC ${RPC_URL}`);
if (!paymaster) {
  log(
    "missing VITE_PAYMASTER_SECRET_KEY; initialize and memo buttons are disabled",
  );
  registerButton.disabled = true;
  memoButton.disabled = true;
  sessionInitButton.disabled = true;
  fundPasskeyButton.disabled = true;
  transferPasskeyButton.disabled = true;
} else {
  void checkPaymaster();
}

function getStoredPasskey(): StoredPasskey | null {
  const stored = window.localStorage.getItem(STORAGE_PASSKEY);
  return stored ? (JSON.parse(stored) as StoredPasskey) : null;
}

function setStoredPasskey(value: StoredPasskey): void {
  window.localStorage.setItem(STORAGE_PASSKEY, JSON.stringify(value));
}

function getStoredSession(): StoredSession | null {
  const stored = window.localStorage.getItem(STORAGE_SESSION);
  return stored ? (JSON.parse(stored) as StoredSession) : null;
}

function setStoredSession(value: StoredSession): void {
  window.localStorage.setItem(STORAGE_SESSION, JSON.stringify(value));
}

function resetLocalState(): void {
  window.localStorage.removeItem(STORAGE_PASSKEY);
  window.localStorage.removeItem(STORAGE_SESSION);
  log("cleared stored passkey metadata");
  renderState();
}

async function checkPaymaster(): Promise<void> {
  try {
    if (!paymaster) {
      throw new Error("VITE_PAYMASTER_SECRET_KEY is not configured");
    }
    const balance = await connection.getBalance(
      paymaster.publicKey,
      "confirmed",
    );
    log(`paymaster balance: ${balance / 1_000_000_000} SOL`);
    renderState();
  } catch (error) {
    log(`paymaster check failed: ${String(error)}`);
  }
}

async function initializePasskey(): Promise<void> {
  try {
    if (!paymaster) {
      throw new Error("VITE_PAYMASTER_SECRET_KEY is not configured");
    }
    const passkeyChallengeContext = await getChallengeContext();
    const { challengeBase64Url } = createInitializePasskeyChallenge({
      payer: paymaster.publicKey,
      recentSlotHash: passkeyChallengeContext.recentSlotHash,
    });
    log(`starting WebAuthn registration for RP ID ${rpId}`);

    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: toArrayBuffer(fromBase64Url(challengeBase64Url)),
        rp: webauthnRp,
        user: {
          id: toArrayBuffer(paymaster.publicKey.toBytes()),
          name: "devnet-paymaster-user",
          displayName: "Devnet Demo User",
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "preferred",
        },
        timeout: 60_000,
        attestation: "direct",
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      throw new Error("registration returned no credential");
    }

    const registration = parseRegistrationCredential(credential);
    let initializationWebauthnData: WebAuthnData = registration;
    if (!isDerSignature(registration.signature)) {
      log(
        "registration attestation did not contain a DER signature; requesting immediate authentication assertion for initialization",
      );
      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: toArrayBuffer(fromBase64Url(challengeBase64Url)),
          allowCredentials: [
            {
              id: toArrayBuffer(new Uint8Array(credential.rawId)),
              type: "public-key",
            },
          ],
          userVerification: "preferred",
          timeout: 60_000,
        },
      })) as PublicKeyCredential | null;

      if (!assertion) {
        throw new Error("authentication fallback returned no credential");
      }

      initializationWebauthnData = parseAuthenticationCredential({
        credential: assertion,
        compressedPublicKey: registration.publicKey,
      });
    }

    const init = buildInitializePasskeyAccount({
      webauthnData: initializationWebauthnData,
      rpId,
      payer: paymaster.publicKey,
      truncatedSlot: passkeyChallengeContext.slot,
      recentSlotHash: passkeyChallengeContext.recentSlotHash,
    });

    const precompile = createSecp256r1Instruction({
      signature: initializationWebauthnData.signature,
      message: buildPrecompileMessage(
        initializationWebauthnData.clientDataJson,
        initializationWebauthnData.authData,
      ),
      publicKey: registration.publicKey,
    });

    const txSignature = await sendSignedInstructions(paymaster, [
      precompile,
      init.instruction,
    ]);

    setStoredPasskey({
      passkeyAccount: init.passkeyAccount.toBase58(),
      credentialId: credentialIdToString(registration.credentialId),
      compressedPublicKey: toBase64Url(registration.publicKey),
      rpId,
    });

    log(`passkey initialized in transaction ${txSignature}`);
    log(`passkey account ${init.passkeyAccount.toBase58()}`);
    renderState();
  } catch (error) {
    log(`initialize failed: ${String(error)}`);
  }
}

async function sendMemoWithPasskey(): Promise<void> {
  try {
    if (!paymaster) {
      throw new Error("VITE_PAYMASTER_SECRET_KEY is not configured");
    }
    const storedPasskey = getStoredPasskey();
    if (!storedPasskey) {
      throw new Error("no passkey metadata found; initialize first");
    }

    const passkeyAccount = new PublicKey(storedPasskey.passkeyAccount);
    const compressedPublicKey = fromBase64Url(
      storedPasskey.compressedPublicKey,
    );
    const memoInstruction = new TransactionInstruction({
      programId: MEMO_PROGRAM_ID,
      // Memo accepts empty account metas. Keeping this empty avoids overlapping
      // the wrapped externally-signed account in the inner instruction payload.
      keys: [],
      data: Buffer.from(`memo via passkey ${new Date().toISOString()}`),
    });

    const executeChallengeContext = await getChallengeContext();
    const { challengeBase64Url } = createExecuteInstructionsChallenge({
      nonceSigner: paymaster.publicKey,
      recentSlotHash: executeChallengeContext.recentSlotHash,
      instructions: [memoInstruction],
    });

    log("starting WebAuthn authentication for memo invocation");

    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: toArrayBuffer(fromBase64Url(challengeBase64Url)),
        allowCredentials: [
          {
            id: toArrayBuffer(fromBase64Url(storedPasskey.credentialId)),
            type: "public-key",
          },
        ],
        userVerification: "preferred",
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      throw new Error("authentication returned no credential");
    }

    const authentication = parseAuthenticationCredential({
      credential,
      compressedPublicKey,
    });

    const wrapped = buildExecuteInstructions({
      webauthnData: authentication,
      passkeyAccount,
      nonceSigner: paymaster.publicKey,
      truncatedSlot: executeChallengeContext.slot,
      recentSlotHash: executeChallengeContext.recentSlotHash,
      instructions: [memoInstruction],
      signerExecutionScheme: SignerExecutionScheme.ExecutionAccount,
    });

    const precompile = createSecp256r1Instruction({
      signature: authentication.signature,
      message: wrapped.precompileMessage,
      publicKey: compressedPublicKey,
    });

    const txSignature = await sendSignedInstructions(paymaster, [
      precompile,
      wrapped.instruction,
    ]);
    log(`memo sent via passkey in transaction ${txSignature}`);
  } catch (error) {
    log(`memo failed: ${String(error)}`);
  }
}

async function fundPasskeyForTransferTest(): Promise<void> {
  try {
    if (!paymaster) {
      throw new Error("VITE_PAYMASTER_SECRET_KEY is not configured");
    }
    const storedPasskey = getStoredPasskey();
    if (!storedPasskey) {
      throw new Error("no passkey metadata found; initialize first");
    }

    const passkeyAccount = new PublicKey(storedPasskey.passkeyAccount);
    const [executionAccount] = deriveExecutionAccount(passkeyAccount);
    const instruction = SystemProgram.transfer({
      fromPubkey: paymaster.publicKey,
      toPubkey: executionAccount,
      lamports: PASSKEY_FUNDING_LAMPORTS,
    });
    const txSignature = await sendSignedInstructions(paymaster, [instruction]);
    const executionBalance = await connection.getBalance(
      executionAccount,
      TRANSACTION_COMMITMENT,
    );
    const passkeyBalance = await connection.getBalance(
      passkeyAccount,
      TRANSACTION_COMMITMENT,
    );
    log(`funded execution account in transaction ${txSignature}`);
    log(`execution account: ${executionAccount.toBase58()}`);
    log(`execution balance: ${executionBalance / LAMPORTS_PER_SOL} SOL`);
    log(`passkey balance: ${passkeyBalance / LAMPORTS_PER_SOL} SOL`);
  } catch (error) {
    log(`fund passkey failed: ${String(error)}`);
  }
}

async function sendTransferWithPasskey(): Promise<void> {
  try {
    if (!paymaster) {
      throw new Error("VITE_PAYMASTER_SECRET_KEY is not configured");
    }
    const storedPasskey = getStoredPasskey();
    if (!storedPasskey) {
      throw new Error("no passkey metadata found; initialize first");
    }

    const passkeyAccount = new PublicKey(storedPasskey.passkeyAccount);
    const [executionAccount] = deriveExecutionAccount(passkeyAccount);
    const compressedPublicKey = fromBase64Url(
      storedPasskey.compressedPublicKey,
    );
    const transferInstruction = SystemProgram.transfer({
      fromPubkey: executionAccount,
      toPubkey: paymaster.publicKey,
      lamports: PASSKEY_TRANSFER_LAMPORTS,
    });
    // For wrapped execution, the runtime must not require a top-level
    // signature from the PDA; the program sets the signer during CPI.
    transferInstruction.keys = transferInstruction.keys.map((meta) =>
      meta.pubkey.equals(executionAccount)
        ? { ...meta, isSigner: false, isWritable: true }
        : meta,
    );

    const executeChallengeContext = await getChallengeContext();
    const { challengeBase64Url } = createExecuteInstructionsChallenge({
      nonceSigner: paymaster.publicKey,
      recentSlotHash: executeChallengeContext.recentSlotHash,
      instructions: [transferInstruction],
    });

    log("starting WebAuthn authentication for passkey transfer");
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: toArrayBuffer(fromBase64Url(challengeBase64Url)),
        allowCredentials: [
          {
            id: toArrayBuffer(fromBase64Url(storedPasskey.credentialId)),
            type: "public-key",
          },
        ],
        userVerification: "preferred",
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null;
    if (!credential) {
      throw new Error("authentication returned no credential");
    }

    const authentication = parseAuthenticationCredential({
      credential,
      compressedPublicKey,
    });

    const wrapped = buildExecuteInstructions({
      webauthnData: authentication,
      passkeyAccount,
      nonceSigner: paymaster.publicKey,
      truncatedSlot: executeChallengeContext.slot,
      recentSlotHash: executeChallengeContext.recentSlotHash,
      instructions: [transferInstruction],
      signerExecutionScheme: SignerExecutionScheme.ExecutionAccount,
    });

    const precompile = createSecp256r1Instruction({
      signature: authentication.signature,
      message: wrapped.precompileMessage,
      publicKey: compressedPublicKey,
    });
    const txSignature = await sendSignedInstructions(paymaster, [
      precompile,
      wrapped.instruction,
    ]);
    log(`execution-account transfer sent in transaction ${txSignature}`);
  } catch (error) {
    log(`execution-account transfer failed: ${String(error)}`);
  }
}

async function initializeSessionKey(): Promise<void> {
  try {
    if (!paymaster) {
      throw new Error("VITE_PAYMASTER_SECRET_KEY is not configured");
    }

    const storedPasskey = getStoredPasskey();
    if (!storedPasskey) {
      throw new Error("no passkey metadata found; initialize first");
    }

    const passkeyAccount = new PublicKey(storedPasskey.passkeyAccount);
    const compressedPublicKey = fromBase64Url(
      storedPasskey.compressedPublicKey,
    );
    const sessionSigner = Keypair.generate();

    await ensureSessionSignerFunded(sessionSigner.publicKey);

    const challengeContext = await getChallengeContext();
    const { challengeBase64Url } = createRefreshSessionKeyChallenge({
      nonceSigner: paymaster.publicKey,
      recentSlotHash: challengeContext.recentSlotHash,
      sessionKey: {
        key: sessionSigner.publicKey.toBytes(),
        expiration: SESSION_DURATION_SECONDS,
      },
    });

    log("starting WebAuthn authentication for session-key refresh");
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: toArrayBuffer(fromBase64Url(challengeBase64Url)),
        allowCredentials: [
          {
            id: toArrayBuffer(fromBase64Url(storedPasskey.credentialId)),
            type: "public-key",
          },
        ],
        userVerification: "preferred",
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null;

    if (!credential) {
      throw new Error("authentication returned no credential");
    }

    const authentication = parseAuthenticationCredential({
      credential,
      compressedPublicKey,
    });
    const refresh = buildRefreshSessionKey({
      webauthnData: authentication,
      passkeyAccount,
      nonceSigner: paymaster.publicKey,
      truncatedSlot: challengeContext.slot,
      recentSlotHash: challengeContext.recentSlotHash,
      sessionKey: {
        key: sessionSigner.publicKey.toBytes(),
        expiration: SESSION_DURATION_SECONDS,
      },
    });
    const precompile = createSecp256r1Instruction({
      signature: authentication.signature,
      message: refresh.precompileMessage,
      publicKey: compressedPublicKey,
    });

    const txSignature = await sendSignedInstructions(paymaster, [
      precompile,
      refresh.instruction,
    ]);

    const nowUnix = Math.floor(Date.now() / 1000);
    setStoredSession({
      sessionSignerSecretKey: toBase64Url(sessionSigner.secretKey),
      sessionSignerPubkey: sessionSigner.publicKey.toBase58(),
      expiresAtUnixSeconds: nowUnix + SESSION_DURATION_SECONDS,
    });

    log(`session key initialized in transaction ${txSignature}`);
    log(`session signer ${sessionSigner.publicKey.toBase58()}`);
    renderState();
  } catch (error) {
    log(`session init failed: ${String(error)}`);
  }
}

async function sendMemoWithSessionKey(): Promise<void> {
  try {
    const storedPasskey = getStoredPasskey();
    if (!storedPasskey) {
      throw new Error("no passkey metadata found; initialize first");
    }

    const storedSession = getStoredSession();
    if (!storedSession) {
      throw new Error("no session key found; initialize session key first");
    }

    const sessionSigner = Keypair.fromSecretKey(
      fromBase64Url(storedSession.sessionSignerSecretKey),
    );

    await ensureSessionSignerFunded(sessionSigner.publicKey);

    const passkeyAccount = new PublicKey(storedPasskey.passkeyAccount);
    const memoInstruction = new TransactionInstruction({
      programId: MEMO_PROGRAM_ID,
      keys: [],
      data: Buffer.from(`memo via session key ${new Date().toISOString()}`),
    });
    const wrapped = buildExecuteInstructionsSessioned({
      passkeyAccount,
      sessionSigner: sessionSigner.publicKey,
      instructions: [memoInstruction],
      signerExecutionScheme: SignerExecutionScheme.ExecutionAccount,
    });

    const txSignature = await sendSignedInstructions(sessionSigner, [wrapped]);
    log(`sessioned memo sent in transaction ${txSignature}`);
  } catch (error) {
    log(`sessioned memo failed: ${String(error)}`);
  }
}

async function sendSignedInstructions(
  payer: Keypair,
  instructions: TransactionInstruction[],
): Promise<string> {
  const latest = await connection.getLatestBlockhash(TRANSACTION_COMMITMENT);
  const transaction = new Transaction({
    feePayer: payer.publicKey,
    recentBlockhash: latest.blockhash,
  }).add(...instructions);
  transaction.sign(payer);
  try {
    const signature = await connection.sendRawTransaction(
      transaction.serialize(),
    );
    await connection.confirmTransaction(
      { signature, ...latest },
      TRANSACTION_COMMITMENT,
    );
    return signature;
  } catch (error) {
    if (error instanceof SendTransactionError) {
      const logs = await error.getLogs(connection);
      if (logs && logs.length > 0) {
        const formattedLogs = logs.join("\n");
        throw new Error(
          `send transaction failed: ${error.message}\nfull logs:\n${formattedLogs}`,
        );
      }
    }
    throw error;
  }
}

async function getChallengeContext(): Promise<{
  slot: number;
  recentSlotHash: Uint8Array;
}> {
  const slotHashesAccount = await connection.getAccountInfo(
    SLOT_HASHES_SYSVAR_ID,
    CHALLENGE_COMMITMENT,
  );
  if (!slotHashesAccount) {
    throw new Error("failed to fetch slot hashes sysvar");
  }

  const data = slotHashesAccount.data;
  if (data.length < 48) {
    throw new Error("slot hashes sysvar account is unexpectedly small");
  }

  const mostRecentSlot = Number(readU64LE(data, 8));
  const recentSlotHash = data.slice(16, 48);

  return {
    slot: truncateSlotForValidator(mostRecentSlot),
    recentSlotHash,
  };
}

async function ensureSessionSignerFunded(
  sessionSigner: PublicKey,
): Promise<void> {
  if (!paymaster) {
    return;
  }

  const balance = await connection.getBalance(
    sessionSigner,
    TRANSACTION_COMMITMENT,
  );
  if (balance >= SESSION_SIGNER_MIN_LAMPORTS) {
    return;
  }

  const latest = await connection.getLatestBlockhash(TRANSACTION_COMMITMENT);
  const transfer = SystemProgram.transfer({
    fromPubkey: paymaster.publicKey,
    toPubkey: sessionSigner,
    lamports: SESSION_SIGNER_TOPUP_LAMPORTS,
  });
  const transaction = new Transaction({
    feePayer: paymaster.publicKey,
    recentBlockhash: latest.blockhash,
  }).add(transfer);
  transaction.sign(paymaster);
  const signature = await connection.sendRawTransaction(
    transaction.serialize(),
  );
  await connection.confirmTransaction(
    { signature, ...latest },
    TRANSACTION_COMMITMENT,
  );
  log(
    `funded session signer ${sessionSigner.toBase58()} with ${SESSION_SIGNER_TOPUP_LAMPORTS / LAMPORTS_PER_SOL} SOL`,
  );
}

function renderState(): void {
  const passkey = getStoredPasskey();
  const executionAccount = passkey
    ? deriveExecutionAccount(
        new PublicKey(passkey.passkeyAccount),
      )[0].toBase58()
    : "not initialized";
  const session = getStoredSession();
  const nowUnix = Math.floor(Date.now() / 1000);
  const sessionStatus = session
    ? session.expiresAtUnixSeconds > nowUnix
      ? `active until ${new Date(session.expiresAtUnixSeconds * 1000).toLocaleString()}`
      : `expired at ${new Date(session.expiresAtUnixSeconds * 1000).toLocaleString()}`
    : "not initialized";

  stateEl.innerHTML = [
    ["rpc", RPC_URL],
    [
      "paymaster",
      paymaster?.publicKey.toBase58() ?? "missing VITE_PAYMASTER_SECRET_KEY",
    ],
    ["external account", passkey?.passkeyAccount ?? "not initialized"],
    ["execution account", executionAccount],
    ["credential", passkey?.credentialId ?? "not initialized"],
    ["rp id", passkey?.rpId ?? rpId],
    ["session signer", session?.sessionSignerPubkey ?? "not initialized"],
    ["session status", sessionStatus],
  ]
    .map(([label, value]) => `<dt>${label}</dt><dd><code>${value}</code></dd>`)
    .join("");
}

function log(message: string): void {
  logEl.textContent =
    `${new Date().toLocaleTimeString()} ${message}\n${logEl.textContent}`.trim();
}

function loadPaymasterFromEnv(): Keypair | null {
  if (!PAYMASTER_SECRET) {
    return null;
  }

  try {
    if (PAYMASTER_SECRET.trim().startsWith("[")) {
      return Keypair.fromSecretKey(
        Uint8Array.from(JSON.parse(PAYMASTER_SECRET) as number[]),
      );
    }

    return Keypair.fromSecretKey(bs58.decode(PAYMASTER_SECRET));
  } catch (error) {
    console.error("failed to parse VITE_PAYMASTER_SECRET_KEY", error);
    return null;
  }
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function readU64LE(data: Uint8Array, offset: number): bigint {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return view.getBigUint64(offset, true);
}

function getRpId(): string {
  const host = window.location.hostname;
  if (host === "127.0.0.1" || host === "[::1]") {
    return "localhost";
  }
  return host;
}

function getWebauthnRp(): PublicKeyCredentialRpEntity {
  if (rpId === "localhost") {
    return { name: "External Signature Demo" };
  }

  return {
    id: rpId,
    name: "External Signature Demo",
  };
}

function isDerSignature(signature: Uint8Array): boolean {
  return signature.length >= 8 && signature[0] === 0x30;
}
