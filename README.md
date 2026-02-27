# Biometric Seedless Smart Wallet

A non-custodial smart wallet using secp256r1 authentication on Stacks.

## Overview

This project implements a seedless authentication mechanism using secp256r1 elliptic curve signatures. Users can authenticate using biometric data stored on their device without exposing seed phrases.

## Features

- **Seedless Authentication**: No seed phrases required
- **Biometric Verification**: Uses device-based keys
- **Non-Custodial**: Users retain full control
- **Replay Protection**: Nonce-based attack prevention
- **Clarity 4**: Uses latest secp256r1-verify function

## Contract Functions

### initialize
Initialize the wallet with owner's public key.

**Parameters:**
- `new-owner-pubkey`: Compressed secp256r1 public key (33 bytes)

### execute-action
Execute an authenticated action.

**Parameters:**
- `action-payload`: The action data to execute
- `signature`: The secp256r1 signature

### verify-signature
Verify a signature without executing an action.

### get-nonce
Get the current nonce value.

### get-owner-pubkey
Get the owner's public key.

### is-initialized
Check if wallet has been initialized.

## Error Codes

| Code | Description |
|------|-------------|
| 100 | Invalid signature |
| 101 | Invalid nonce |
| 102 | Unauthorized |
| 103 | Already initialized |
| 104 | Not initialized |
| 105 | Zero pubkey |

## Development

```bash
npm install
npm test
```

## Security

- Keep your private keys secure
- Only initialize once
- Use unique nonces for each transaction
