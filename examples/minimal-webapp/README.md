# Minimal Web App Demo

This is a super minimal browser demo for the TypeScript SDK. It runs against devnet, creates a passkey-backed account, then wraps and submits a Memo instruction through the External Signature Program.

## What it demonstrates

- devnet paymaster signing from Vite env
- WebAuthn registration for passkey initialization
- WebAuthn authentication for wrapped instruction execution
- memo invocation through the External Signature Program using the TypeScript SDK

## Prerequisites

1. Make sure the External Signature Program is deployed on devnet at:

```text
ExtSgUPtP3JyKUysFw2S5fpL5fWfUPzGUQLd2bTwftXN
```

2. Create `examples/minimal-webapp/.env.local` from the example file:

```bash
cp examples/minimal-webapp/.env.example examples/minimal-webapp/.env.local
```

Set:

- `VITE_RPC_URL` to a devnet RPC, or leave the default
- `VITE_PAYMASTER_SECRET_KEY` to a devnet-funded keypair

The secret key can be either:

- a JSON array of 64 bytes
- a base58-encoded secret key

3. Run the web app:

```bash
cd examples/minimal-webapp
npm install
npm run dev -- --host localhost
```

4. Open the local Vite URL on `localhost` in a browser that supports WebAuthn.

## Notes

- The app exposes the paymaster secret to browser code. This is strictly for demo use.
- The app stores only passkey metadata in `localStorage`.
- On `localhost`, the app lets the browser use the current origin as the WebAuthn RP instead of forcing an explicit `rp.id`. For non-localhost hosts, it sets `rp.id` explicitly.
- The memo flow uses `SignerExecutionScheme.ExternalAccount`, so the wrapped Memo instruction is signed by the passkey account directly.
