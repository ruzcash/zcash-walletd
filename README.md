`zcash-walletd` is a shielded only (sapling, orchard, ironwood, UA) REST wallet
for zcash.

Primary intended to work with the BTCPayServer payment gateway,
it offers a REST interface that can be useful in other scenarios.

For instance, it implements a subset of the `monero-wallet` API,
which allows it to be used interchangeably in some cases.

## Features

### Account Management

Create diversified addresses on demand and map them to account #
and sub account #. BTCPay associates each store to an account and
each invoice into a sub account.

Millions of accounts and sub accounts are supported without significant performance loss.

### Monitor the Blockchain and detect incoming payments

When a customer pays an invoice, `zcash-walletd` sees the received
notes and makes a REST/POST request to notify the payment gateway.

Partial payments are supported.

### Security

Wallet is view only and does not contain the main account seed or secret key.

## Build

```
# cargo build --release
```

## Configuration

- `zcash-walletd` looks for an environment variable `VK` that must contains the viewing key of the wallet
- Optionally, if a `BIRTH_HEIGHT` variable is present it will indicate the starting scan height
- `BIRTH_HEIGHT` is only used for the initial sync

## Command line args

- Passing `--rescan` will instruct `zcash-walletd` to resync from the birth height or the sapling activation
height

## Docker

To build a docker image: Run from the project directory

```
# ./docker/build.sh
```

The latest image is available on DockerHub under `hhanh00/zcash-walletd:latest`

## Orchard
Support for Orchard and UA was added in 1.1.2. You MUST delete the database file
because the previous schema is not compatible.

## NU6.3 (Ironwood)

NU6.3 introduces the **Ironwood** shielded pool. Ironwood reuses Orchard's keys, addresses and
action encoding, so **no new address type and no re-issuing of addresses is needed**: an
Ironwood note is received at an ordinary Orchard receiver of a UA. What differs is that
Ironwood notes use their own note-plaintext version and live in their own commitment tree, and
that **once NU6.3 activates, payments to an Orchard receiver are routed to the Ironwood pool**.
A wallet that scans only the Orchard bundle therefore stops seeing its own incoming payments
after activation.

`zcash-walletd` scans both pools. Two things are required of the deployment:

- **Upgrade `lightwalletd`.** Ironwood data only rides in compact blocks when the client asks
  for it via `BlockRange.poolTypes`, which is part of the versioned
  [lightwallet-protocol](https://github.com/zcash/lightwallet-protocol). `zcash-walletd`
  requests it only from a server that advertises `LightdInfo.lightwalletProtocolVersion`, since
  a legacy server may reject or misinterpret the field. Against a legacy (<= v0.4.x) server it
  falls back to the Sapling + Orchard default and logs a warning — correct before activation,
  but Ironwood receives will be **invisible** after it. Upgrade the server before the NU6.3
  activation height.
- **No database reset is needed.** The `received_notes` table gains a `pool` column on first
  start (note positions are only unique within a pool's own commitment tree, and Ironwood's
  restarts at zero); the migration runs automatically and preserves existing rows.

Activation is consensus-height driven — there is no build flag and no configuration switch.
