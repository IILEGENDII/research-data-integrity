# Threat model

## Assets and trust anchors

The protected record is the list of relative file names, lengths, and SHA-256 digests at baseline creation. The signed payload also records the format, digest algorithm, and claimed creation time. The signing private key authorizes baselines. A separately obtained public key identifies the expected signer. Store the baseline and its fingerprint history independently when its age or sequence matters.

## Inputs an attacker might change

A dataset writer could replace bytes while preserving length, rename files, remove results, add paths, or introduce links. Someone with write access to the manifest could change the inventory, replace the signature, or supply a different public key. The verifier validates the document and checks the expected key and signature before walking the dataset. It discovers paths from the filesystem and compares records in memory. It never opens a dataset path named by a manifest entry.

## Assumptions

The signing host, verifying host, OS, dependencies, output parent directories, and trusted-key distribution must be under appropriate control. An authorized researcher chooses a known-good baseline and an explicit, stable local dataset. A signed baseline taken after corruption faithfully records that corruption. A writer who restores bytes before a check leaves no persistent difference for hashing to detect.

## What a result establishes

A completed signed comparison can establish that the observed files matched the authenticated inventory during the scan. A digest mismatch identifies the file and the expected and observed bytes' digests. It gives no identity, motive, or time of modification. An expected simulation rerun and an unintended edit can produce the same finding. Record the report, confirm which baseline and public key were used, and examine independent change records before drawing conclusions.

An attacker with the signing key can authorize arbitrary inventories. An attacker who replaces the verifier's trust anchor can choose their own signer. If both forms of custody fail, discard trust derived from them and re-establish the baseline from independently checked materials. A valid old manifest can be replayed. The tool supplies neither a trusted timestamp nor monotonic version history.

Manifests expose filenames, sizes, and digests. Encryption and access control protect confidentiality. Independent backups retain bytes for recovery. This tool supplies neither service. [Operational boundaries](limitations.md)
