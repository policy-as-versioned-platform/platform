# Windows Hello for Business on the vTPM Windows 11 EUD — narrated honestly

**Scope, 2026-10-21:** the actor identity/access plane is shelved; no live
attestation is established by this runbook.

**Ticket 20.** Demonstrates the Windows-side half of "device (EUD), same graded
posture" (spec: Enforcement gradient & three-actor identity). WHfB is the
*local* Windows sign-in gate (TPM-bound PIN/biometric) on the vTPM'd VM;
`tpm_devid` (below) is what turns that VM's TPM into an estate device SVID.
They compose but are not the same thing — don't conflate them on stage.

## What WHfB proves, on this VM

Windows Hello for Business provisions a TPM-bound asymmetric key pair per user:
the private key never leaves the TPM (here: the swtpm-emulated vTPM), sign-in
requires a local gesture (PIN, or biometric if the host passes one through),
and the key cannot be extracted or replayed off-box. That's genuine
TPM-key-non-exportability — the same shape of guarantee as the Mac's
Secure-Enclave WebAuthn key in `../access/device/secure-enclave.md`, on a
different actor (Windows local sign-in vs. a WebAuthn browser credential).

## Enrolment (venue steps — not run headless)

1. `build-vm.sh` prepares the disk + vTPM state (offline, this repo).
2. Boot the VM with the printed `qemu-system-x86_64` command (or import into
   UTM's GUI and enable "Trusted Platform Module" under System), install
   Windows 11, and let it discover the vTPM as a normal TPM 2.0 device
   (`tpm.msc` should show "Ready for use").
3. Join or hybrid-join the VM to the estate's directory (Dex serves OIDC for
   the estate; a full AD/Entra join is out of scope here — narrate this step,
   see the caveat below).
4. **Settings > Accounts > Sign-in options > Windows Hello** — enrol a PIN.
   `tpm.msc` / `certutil -tpminfo` confirms the WHfB key is TPM-resident.

## Device identity and the offline decision fixture

WHfB local sign-in and an estate device SVID are separate signals. The actor
plane remains shelved, including the SPIRE/Pomerium integration. The retired
`../access/access.py` entrypoint does not authenticate either signal or grant
access. The included `../break-glass/` fixture takes an explicit device input;
it does not read a live SVID or Windows sign-in.

```bash
# Included financial fixture, not an observed Windows identity or access check.
python3 ../break-glass/break-glass.py decide ../break-glass/scenarios/ludlow-patient-data.json --oidc --webauthn --device fresh
python3 ../break-glass/break-glass.py decide ../break-glass/scenarios/ludlow-patient-data.json --oidc --webauthn --device none
```

The first fixture returns ALLOW and the second DENY under its unchanged global
bands. Neither establishes a live device, per-party calibration or integration.

## The honest caveat (say this on stage)

The vTPM's endorsement key is **swtpm-emulated**, minted fresh the first time
the VM boots — it chains to no manufacturer CA. `tpm_devid`'s
`endorsement_ca_path` (`../access/device/spire-tpm-devid-values.yaml`) is
therefore pointed at swtpm's *self-signed* EK cert for this demo, not a real
TPM vendor root (Infineon/STMicro/Nuvoton). **The mechanism is identical** to
a real fleet laptop — WHfB's TPM-key-non-exportability and `tpm_devid`'s
proof-of-residency challenge both run for real against the vTPM — only the
*trust anchor* the server verifies against is a demo root instead of a
manufacturer root. Swap `devid_ca_path`/`endorsement_ca_path` for the real
manufacturer CAs and the same config attests a genuine fleet device. This
mirrors the Linux EUD exactly (see `vms/linux-vtpm.json`) and the Mac's honest
split in `../access/device/secure-enclave.md`.
