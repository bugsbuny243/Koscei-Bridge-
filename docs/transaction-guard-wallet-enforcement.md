# Transaction Guard Wallet Enforcement v1

Koschei Wallet Enforcement v1 is a strict client-side signing middleware for Solana dApps that integrate Koschei Transaction Guard.

The server remains read-only and no-custody. The enforcement SDK wraps the dApp's wallet adapter/provider and prevents protected signing methods from reaching the wallet unless the exact serialized transaction receives a complete Koschei decision.

## Security boundary

The SDK enforces only wallet calls routed through the wrapped provider returned by `createGuardedWallet`.

It does not claim universal wallet protection:

- a malicious dApp can bypass an optional SDK and call the raw wallet provider directly
- another browser tab or application is outside this integration boundary
- the SDK is not a wallet firmware feature, browser extension or wallet-standard interceptor
- users must not treat SDK integration as proof that every transaction from the site is protected

Wallet-native or extension-level interception is the next stronger enforcement boundary.

## Decision behavior

| Guard result | SDK behavior |
| --- | --- |
| `allow` with `guard_complete=true` | The exact analyzed transaction may reach the wallet. |
| `warn` with `guard_complete=true` | Requires explicit approval bound to the exact transaction fingerprint. |
| `block` | The wallet signing method is never called. |
| `withhold`, incomplete Guard evidence, provider failure or malformed response | The wallet signing method is never called. |

Unknown actions, `ok=false`, a missing `guard_complete`, response identity mismatches and stale decisions are treated as `withhold`.

## Integrity contract

Before signing, the SDK:

1. serializes the transaction without requiring every signature
2. computes the same `txf_...` fingerprint contract used by the Guard API
3. binds the wallet, network, policy and optional signed UI intent to that fingerprint
4. sends the serialized transaction to `/api/v1/shield/transaction`
5. verifies the response fingerprint, wallet and network
6. requires a complete `allow` or fingerprint-bound `warn` approval
7. serializes the transaction again immediately before the wallet call
8. blocks if any transaction byte changed

After `signTransaction` or `signAllTransactions`, the SDK compares the signed transaction message with the pre-sign message. A wallet/provider that changes instructions, accounts, amounts, programs or the recent blockhash while signing is rejected.

## Strict combined sign-and-send policy

`sendTransaction` and `signAndSendTransaction` are disabled by default.

Those combined methods can broadcast before the SDK can verify the signed message. Strict applications should use:

1. the guarded `signTransaction` or `signAllTransactions` method
2. post-sign message verification performed by the SDK
3. a separate RPC submission step controlled by the application

`allowCombinedSignAndSend=true` is an explicit reduction of this security guarantee and should not be enabled for high-assurance flows.

## Browser integration

Load the SDK and wrap the connected wallet adapter/provider:

```html
<script src="/js/koschei-wallet-enforcement.js"></script>
<script>
  const guardedWallet = KoscheiWalletEnforcement.createGuardedWallet(rawWallet, {
    endpoint: "/api/v1/shield/transaction",
    network: "solana-mainnet",
    intentMode: "required",

    policyProvider: async ({ transactionFingerprint }) => ({
      ui_summary: {
        title: "Swap 10 USDC",
        transaction_fingerprint: transactionFingerprint
      },
      expected_programs: ["JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"],
      required_programs: [],
      blocked_programs: [],
      accounts: [
        {
          address: "INPUT_TOKEN_ACCOUNT",
          mint: "USDC_MINT",
          role: "input",
          decimals: 6,
          maximum_spend_raw: "10000000"
        },
        {
          address: "OUTPUT_TOKEN_ACCOUNT",
          mint: "OUTPUT_MINT",
          role: "output",
          minimum_receive_raw: "950000"
        }
      ]
    }),

    onWarn: async ({ transactionFingerprint, explanation }) => {
      const approved = await showExplicitKoscheiWarning(explanation);
      return { approved, fingerprint: transactionFingerprint };
    }
  });

  const signed = await guardedWallet.signTransaction(transaction);
```

The application must stop using the raw wallet object after wrapping it. Every protected signing path must receive the guarded object through dependency injection.

## Signed UI intent

`intentMode: "required"` is the default.

The SDK creates the canonical `koschei-ui-intent-v1` payload and asks the wallet to sign it with `signMessage`. The signature binds:

- wallet and signer
- exact transaction fingerprint
- network
- normalized program policy
- normalized account amount policy
- UI origin
- SHA-256 hash of the human-visible UI summary
- short issuance and expiration timestamps
- unique intent ID and nonce

The canonical JSON field order and RFC3339 second-level timestamps match the Go verifier. The default lifetime is five minutes and the maximum is thirty minutes.

A wallet without `signMessage` cannot satisfy required intent mode; signing is withheld rather than silently weakening the contract.

## Authentication

Do not embed a long-lived Koschei API key in public browser JavaScript.

Preferred deployments use one of these patterns:

- a same-origin backend-for-frontend route that authenticates the user and forwards the Guard request
- short-lived tenant credentials issued by the application's backend
- an existing authenticated same-origin session with `headersProvider`

Example:

```js
headersProvider: async () => ({
  Authorization: `Bearer ${await getShortLivedSessionToken()}`
})
```

The browser SDK supports `apiKey` for controlled or local integrations, but it is not a safe secret-storage mechanism.

## Failure behavior

The SDK fails closed for:

- Guard timeout or network failure
- non-JSON response
- response transaction fingerprint mismatch
- response wallet or network mismatch
- incomplete evidence
- expired decision
- transaction mutation during policy or intent preparation
- transaction mutation while awaiting Guard
- transaction mutation before wallet signing
- wallet message mutation during signing
- WARN approval missing the exact fingerprint
- invalid batch response

A missing signal never means safe.

## Batch signing

`signAllTransactions` is all-or-nothing:

- every transaction is independently serialized and assessed
- every WARN receives its own fingerprint-bound approval
- no wallet batch call occurs if any transaction is blocked or withheld
- all transaction bytes are checked again before the single wallet batch call
- every returned signed message is verified

## API surface

The UMD/CommonJS module exports:

- `createGuardedWallet(wallet, options)`
- `createSignedIntent(wallet, details, options)`
- `normalizePolicy(policy)`
- `transactionFingerprintFromBase64(base64)`
- `serializeTransaction(transaction)`
- `serializeMessage(transaction)`
- `KoscheiEnforcementError`
- `KoscheiBlockedError`
- `KoscheiWithheldError`

The wrapper also exposes:

- `koscheiEnforcementVersion`
- `getKoscheiLastDecision()`

## Verification

Required CI executes:

```bash
node scripts/verify-wallet-enforcement.js
```

The contract verifies that blocked and withheld transactions never call the wallet, WARN approval is fingerprint-bound, byte mutation is rejected, signed-message mutation is rejected, batches are atomic and combined sign-and-send methods are disabled in strict mode.
