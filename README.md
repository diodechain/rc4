# RC4

Pure Elixir RC4 stream cipher compatible with `:crypto.crypto_one_time(:rc4, key, data, _encrypt?)`.

OpenSSL 3 dropped RC4 from the default provider, so OTP builds linked against it no longer expose `:rc4` through `:crypto`. This library provides a drop-in keystream implementation for legacy obfuscation paths that must keep reading existing RC4-encrypted data.

## Usage

```elixir
ciphertext = RC4.apply(key, plaintext)
plaintext = RC4.apply(key, ciphertext)
```

RC4 is symmetric: applying the same key twice restores the original data.

## Tests

Vectors are verified against [RFC 6229](https://www.rfc-editor.org/rfc/rfc6229). A separate CI job runs parity tests against `:crypto` on OTP 25 linked with OpenSSL that still exposes RC4.

If the parity job preflight fails (runner no longer ships RC4), pin an OTP version documented in `.github/workflows/ci.yml`.

## License

MIT — see [LICENSE.md](LICENSE.md).
