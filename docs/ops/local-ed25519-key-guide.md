# Local Ed25519 key guide (owner / approver)

wiki-spike Second-Brain decision records require **two distinct Ed25519 keys**:
owner and approver. Signatures are 64-byte detached Ed25519 over

`wiki-spike.second-brain.decision.v1\0` + canonical decision body.

This guide is for **local bootstrap / throwaway** keys. Production keys must be
generated and held on separate machines by separate roles.

Related: `docs/ops/decision-record-signing-runbook.md`.

---

## Rules

1. Private keys **never** enter the git repository, chat logs, or artifacts tree.
2. Owner and approver must be **different key_ids and different public keys**.
3. Exchange only `*.pub.raw` (32-byte raw public keys), never `.pem` private keys.
4. Use `python3.12` with `scripts/second_brain_decision.py` for signing bytes.
5. OpenSSL Ed25519 sign requires `-rawin`.

---

## 1. Create a key directory outside the repo

```sh
mkdir -p ~/keys/wiki-spike-local
chmod 700 ~/keys/wiki-spike-local
cd ~/keys/wiki-spike-local
```

Do **not** put this directory inside the checkout.

---

## 2. Generate owner and approver private keys

```sh
openssl genpkey -algorithm ed25519 -out owner.pem
openssl genpkey -algorithm ed25519 -out approver.pem
chmod 600 owner.pem approver.pem
```

Optional passphrase-protected form (recommended on shared laptops):

```sh
openssl genpkey -algorithm ed25519 -aes-256-cbc -out owner.pem
```

---

## 3. Export 32-byte raw public keys

`openssl pkey -pubout -outform DER` emits 44-byte SubjectPublicKeyInfo.
The contract wants the trailing **32 raw bytes**.

```sh
openssl pkey -in owner.pem -pubout -outform DER | tail -c 32 > owner.pub.raw
openssl pkey -in approver.pem -pubout -outform DER | tail -c 32 > approver.pub.raw
wc -c *.pub.raw   # both must be 32
```

Base64 form used in decision JSON:

```sh
base64 < owner.pub.raw | tr -d '\n'; echo
base64 < approver.pub.raw | tr -d '\n'; echo
```

---

## 4. Sign decision bytes (runbook path)

From the repo root:

```sh
# body.json already filled (no REPLACE-WITH placeholders)
python3.12 scripts/second_brain_decision.py signing-bytes \
  --body body.json --out DB-05.signing.bin

# each role signs the same bytes with their own key
openssl pkeyutl -sign -inkey ~/keys/wiki-spike-local/owner.pem \
  -rawin -in DB-05.signing.bin -out owner.sig
openssl pkeyutl -sign -inkey ~/keys/wiki-spike-local/approver.pem \
  -rawin -in DB-05.signing.bin -out approver.sig
wc -c owner.sig approver.sig   # both must be 64

python3.12 scripts/second_brain_decision.py envelope \
  --role owner --key-id owner \
  --public-key ~/keys/wiki-spike-local/owner.pub.raw \
  --signature owner.sig > owner.env.json

python3.12 scripts/second_brain_decision.py envelope \
  --role approver --key-id approver \
  --public-key ~/keys/wiki-spike-local/approver.pub.raw \
  --signature approver.sig > approver.env.json

python3.12 scripts/second_brain_decision.py assemble \
  --body body.json \
  --signature owner.env.json \
  --signature approver.env.json \
  --out artifacts/product-release/second-brain-v1/local-boot/decisions/DB-05.json

python3.12 scripts/second_brain_decision.py verify \
  --record artifacts/product-release/second-brain-v1/local-boot/decisions/DB-05.json
```

`assemble` reorders to **approver then owner**, verifies both signatures, and
refuses reused identities.

---

## 5. What already exists on this machine

Local bootstrap keys used for
`artifacts/product-release/second-brain-v1/local-boot/`:

```text
~/keys/wiki-spike-local/owner.pem
~/keys/wiki-spike-local/approver.pem
~/keys/wiki-spike-local/owner.pub.raw
~/keys/wiki-spike-local/approver.pub.raw
```

Public keys only are recorded in:

```text
artifacts/product-release/second-brain-v1/local-boot/public-keys.json
```

Rotate by generating new PEMs, re-exporting `.pub.raw`, and re-signing records.
Delete old PEMs with `rm -P` on macOS when retiring throwaway keys.

---

## 6. Safety checklist

- [ ] `*.pem` is outside git status
- [ ] `.gitignore` still ignores `*.key` (add local key dirs if you keep them under home only)
- [ ] owner.pub.raw and approver.pub.raw are each 32 bytes
- [ ] signatures are each 64 bytes
- [ ] `second_brain_decision.py verify` returns `signatures_verified: true`
- [ ] production approval never reuses these throwaway keys
