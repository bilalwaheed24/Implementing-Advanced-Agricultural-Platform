# Hyperledger Fabric mirror

The platform's own ledger anchors every traceability record on a single node. This folder
adds a **real Hyperledger Fabric 2.5 network** next to it: each anchor (record key + SHA-256
content hash) is also written to Fabric, where peers of **two organisations must both
endorse** the write (`AND('Org1MSP.peer','Org2MSP.peer')`). A record changed in the
database then fails verification against Fabric too, and the platform's own signing keys
cannot rewrite the Fabric copy.

```
API ──(after each local anchor, background)──► bridge :8300 ──gRPC──► peer0.org1 ─┐
                                                                     peer0.org2 ─┤ endorse
                                                                       orderer ◄─┘ commit
```

| Part | What it is |
|---|---|
| `chaincode/absp-anchor` | Node.js chaincode: `AnchorRecord`, `VerifyRecord`, `ReadRecord`, `GetHistory`. Stores hashes and ids only, never business data. |
| `gateway` | Small HTTP service using the official Fabric Gateway SDK with an Org1 identity. The API calls it with a bearer token. |
| `../scripts/fabric_up.sh` | Downloads Fabric 2.5.16, starts the test network (2 orgs, Raft orderer, CAs), deploys the chaincode, starts the bridge, writes `FABRIC_BRIDGE_URL`/`FABRIC_BRIDGE_TOKEN` into `.env`. |
| `../scripts/fabric_down.sh` | Stops the bridge and removes the network. |

## Run it

```bash
./scripts/fabric_up.sh          # first run downloads ~2 GB of images
./scripts/run_local.sh          # restart the platform so it picks up FABRIC_BRIDGE_URL
```

Open **Blockchain** in the UI: the *Hyperledger Fabric network* card shows the connection and
every mirrored anchor with its Fabric transaction id. `POST /api/v1/blockchain/verify-record`
now returns a second verdict under `fabric`, read from the Fabric network.

Docker stack instead of `run_local.sh`: `BRIDGE_HOST=0.0.0.0 ./scripts/fabric_up.sh`, then
`COMPOSE_FABRIC_BRIDGE_URL=http://host.docker.internal:8300 docker compose up -d`.

## Tests

```bash
cd fabric/chaincode/absp-anchor && npm install && npm test   # chaincode logic
cd fabric/gateway && npm install && npm test                 # bridge HTTP layer
python3 -m pytest backend/tests/test_fabric_bridge.py -q     # API mirroring and verification
```

## Honest scope

This is Fabric's own *test network*: both organisations run on one machine, and the bridge
holds an Org1 identity. It proves real multi-organisation endorsement and an independent
copy of every anchor. A production consortium would run each organisation's peers on its
own infrastructure, with its own CA and keys.
