# Container Distribution & CI/CD Guide

NoraSign is distributed as a lightweight container image for `linux/amd64` adhering to the container execution contract in Table 2.13.

## Container Image Details

- **Public Registry**: `ghcr.io/brianhadianstei23/norasign`
- **Release Tag**: `1.0.0`
- **Digest Pinning**: Recommended for immutability and supply-chain integrity:
  ```bash
  docker pull ghcr.io/brianhadianstei23/norasign:1.0.0
  ```

---

## Container Execution Model

The container image directly invokes the `norasign` CLI. No runtime compilers or network connectivity are needed.

### Running with Zero Network Access (`--network none`)
All dependencies (such as Python and `cryptography`) are bundled within the container image:

```bash
docker run --rm --network none \
    --user "$(id -u):$(id -g)" \
    ghcr.io/brianhadianstei23/norasign:1.0.0 --version
```

### File Mount Contract
- Artifact input directory mounted as read-only (`:ro`).
- Output bundle directory mounted read-write (`/output`).
- Signer private key mounted as a read-only file (`/run/signing.key.pem:ro`).

```bash
docker run --rm --network none \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" \
  -v "$PWD/out:/output" \
  -v "$SIGNING_KEY_FILE:/run/signing.key.pem:ro" \
  ghcr.io/brianhadianstei23/norasign:1.0.0 sign \
  --file /input/contoh-app.zip \
  --package contoh-app \
  --version 1.0.0 \
  --key /run/signing.key.pem \
  --out /output/release.bundle.json
```
