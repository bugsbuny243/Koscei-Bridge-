# Transaction Guard production enforcement trust anchor

Koschei wallet enforcement verifies short-lived Guard permits against an out-of-band pinned Ed25519 public key.

## Active production key

The active key ID and base64 public key are intentionally committed in:

```text
public/js/koschei-enforcement-trust-anchor.js
```

That file is the single source of truth for the browser trust anchor. The public key is not secret.

The matching private key must exist only as the Railway secret:

```text
TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY
```

Never commit, log, screenshot or transmit the private key.

The production permit lifetime is 45 seconds.

## Browser loading order

```html
<script src="/js/koschei-wallet-enforcement.js"></script>
<script src="/js/koschei-enforcement-permit-verifier.js"></script>
<script src="/js/koschei-enforcement-trust-anchor.js"></script>
<script src="/js/koschei-wallet-enforcement-verified.js"></script>
```

`createPermitVerifiedWallet` uses the production trust anchor automatically unless the integration explicitly supplies a different pinned key set or resolver.

A public key returned inside the Guard response is never accepted as the trust source. It is compared with the already-pinned key and any mismatch fails closed.

## Railway variables

```text
TRANSACTION_GUARD_ENFORCEMENT_KEY_ID=<CURRENT_KEY_ID from trust-anchor.js>
TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS=45
TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY=<sealed Railway secret>
```

Do not enable `TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT=true` until the production client uses the verified wallet wrapper and the pinned key deployment is confirmed.

## Rotation procedure

1. Generate a new Ed25519 key pair offline.
2. Add the new public key to the pinned key map while retaining the old public key.
3. Deploy clients containing both trusted keys.
4. Replace the Railway private key and key ID.
5. Confirm newly issued permits use the new key ID and verify successfully.
6. After the maximum client rollout window, remove the old public key in a later release.

Never replace the Railway signing key before clients trust the new public key. Doing so would cause valid Guard decisions to fail closed.

## CI contract

`Enforcement Trust Anchor CI` verifies:

- the exact production key ID and public key from the trust-anchor module
- the Ed25519 public key is exactly 32 bytes
- the verified wrapper exposes the active production key ID
- an attacker key reusing the production key ID is rejected
