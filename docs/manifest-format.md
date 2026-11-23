# Manifest format, version 1

A UTF-8 JSON envelope has exactly two properties, `payload` and `signature`. Property order and surrounding JSON whitespace can vary on input. Duplicate properties, unexpected properties, floats, non-finite numbers, and invalid scalar types are rejected.

| Location | Required value |
| --- | --- |
| payload.schema_version | Integer 1 |
| payload.algorithm | String `sha256` |
| payload.created_at | Valid UTC calendar date and time with whole seconds, `YYYY-MM-DDTHH:MM:SSZ` |
| payload.files | Array sorted by ascending Unicode code-point order of the full normalized path |
| files[].path | Unique relative path in the portable subset below |
| files[].size | Integer byte length, 0 through 9,223,372,036,854,775,807 |
| files[].sha256 | Exactly 64 lowercase hexadecimal digits, SHA-256 over file bytes |
| signature | JSON null for explicit unsigned baselines, otherwise the object below |
| signature.algorithm | String `ed25519` |
| signature.public_key_fingerprint | `sha256:` followed by 64 lowercase hex digits, SHA-256 over the raw public key |
| signature.value | Standard, canonically padded Base64 encoding of the 64-byte Ed25519 signature |

### Path and parser limits

Paths use Unicode NFC and forward slashes. They cannot be absolute, drive-qualified, empty, contain dot or parent components, end a component with a space or dot, contain a control or nonprinting character, or use reserved Windows characters or device names. Case-folded collisions and file/directory prefix conflicts are rejected on every platform, including conflicting directory spellings. Each component may occupy up to 255 UTF-8 bytes. The full path may occupy up to 4,096 bytes across up to 64 components.

The reader accepts at most 32 MiB per manifest, 8 MiB of aggregate UTF-8 path bytes, and eight levels of JSON nesting. It bounds token length and structural punctuation before full parsing. The file and directory entry budget defaults to 100,000, configurable with `--max-entries` up to 250,000. Unknown schema versions, digest algorithms and signature algorithms fail closed. A future incompatible representation needs a new schema version and a deliberate reader update.

### Bytes covered by the signature

Serialize exactly the payload as below. Dictionary keys are sorted recursively. Retain array order, escape non-ASCII as JSON Unicode escapes, use lowercase escape digits, omit insignificant whitespace, and append no line ending. Ed25519 signs those bytes directly. The on-disk envelope may have a trailing newline.

```python
json.dumps(
    payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
).encode("utf-8")
```

The signature metadata selects the supported scheme and must match the fingerprint of the independently supplied public key. The verifier compares the fingerprint and validates the signature before scanning. Missing `signature` is a schema error. A null signature always fails when a public key is designated, including when unsigned mode is also requested. Explicit unsigned verification with no trusted key cannot detect removal of a signature in favor of null. It reports `unauthenticated`.

### Generated vector

This vector signs the inventory for a file containing the ten bytes `synthetic\n`. The generator created a fresh Ed25519 key in memory. The timestamp is fixed example input. The file below contains the generated values, including the PEM public key and envelope. The test verifies the saved signature and independently checks the file digest. Run `python -m pytest -q tests/test_vector.py`. [Machine-readable vector](../tests/vectors/ed25519-v1.json) · [Generator and test](../tests/test_vector.py)

```json
{
  "envelope": {
    "payload": {
      "schema_version": 1,
      "algorithm": "sha256",
      "created_at": "2026-01-01T00:00:00Z",
      "files": [
        {
          "path": "sample.txt",
          "size": 10,
          "sha256": "18c4f85a180cf29ddc1f8e3a3143ff54d643d1c306dbe610f4f70482632071d4"
        }
      ]
    },
    "signature": {
      "algorithm": "ed25519",
      "public_key_fingerprint": "sha256:a9d50a93ca8ce23b8adb7c226c3368be2331203aa926417a57a6ac80a604db11",
      "value": "5zSsmVDDduC4rug9A7c62Uz8Kw/wX9yrzGNovDH9wRVtEYbE4FnssFLacO7tWj0dv1gq2sunaFvD8eMZdRJaCw=="
    }
  },
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqcW+4AkSD8ZNfASA6EeTcMhEZX5m2gF5f24PYPsyayo=\n-----END PUBLIC KEY-----\n"
}
```
