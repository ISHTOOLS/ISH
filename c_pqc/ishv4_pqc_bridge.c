/*
 * ishv4_pqc_bridge.c
 *
 * Gercek Open Quantum Safe (liboqs) kutuphanesini kullanan komut satiri
 * kopru araci. Burada hicbir matematik simule edilmiyor - dogrudan NIST'in
 * standartlastirdigi ML-KEM-1024 (FIPS 203) ve ML-DSA-87 (FIPS 204)
 * algoritmalarinin liboqs implementasyonu cagriliyor.
 *
 * Kullanim:
 *   ishv4_pqc_bridge kem-keygen
 *   ishv4_pqc_bridge kem-encaps  <public_key_hex>
 *   ishv4_pqc_bridge kem-decaps  <secret_key_hex> <ciphertext_hex>
 *   ishv4_pqc_bridge sig-keygen
 *   ishv4_pqc_bridge sig-sign    <secret_key_hex> <message>
 *   ishv4_pqc_bridge sig-verify  <public_key_hex> <message> <signature_hex>
 *
 * Cikti JSON olarak stdout'a yazilir, boylece Node.js tarafindan kolayca
 * cocuk process olarak cagrilip parse edilebilir.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) sprintf(out + i * 2, "%02x", bytes[i]);
    out[len * 2] = '\0';
}

static size_t hex_to_bytes(const char *hex, uint8_t *out) {
    size_t len = strlen(hex) / 2;
    for (size_t i = 0; i < len; i++) sscanf(hex + i * 2, "%2hhx", &out[i]);
    return len;
}

static void fail(const char *msg) {
    printf("{\"success\":false,\"error\":\"%s\"}\n", msg);
    exit(1);
}

static void cmd_kem_keygen(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) fail("ML-KEM-1024 not available in this liboqs build");

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) fail("keygen failed");

    char *pk_hex = malloc(kem->length_public_key * 2 + 1);
    char *sk_hex = malloc(kem->length_secret_key * 2 + 1);
    bytes_to_hex(pk, kem->length_public_key, pk_hex);
    bytes_to_hex(sk, kem->length_secret_key, sk_hex);

    printf("{\"success\":true,\"algorithm\":\"%s\",\"publicKeyHex\":\"%s\",\"secretKeyHex\":\"%s\","
           "\"publicKeyBytes\":%zu,\"secretKeyBytes\":%zu}\n",
           kem->method_name, pk_hex, sk_hex, kem->length_public_key, kem->length_secret_key);

    free(pk); free(sk); free(pk_hex); free(sk_hex);
    OQS_KEM_free(kem);
}

static void cmd_kem_encaps(const char *pk_hex) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) fail("ML-KEM-1024 not available");

    uint8_t *pk = malloc(kem->length_public_key);
    size_t pk_len = hex_to_bytes(pk_hex, pk);
    if (pk_len != kem->length_public_key) fail("invalid public key length");

    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) fail("encapsulation failed");

    char *ct_hex = malloc(kem->length_ciphertext * 2 + 1);
    char *ss_hex = malloc(kem->length_shared_secret * 2 + 1);
    bytes_to_hex(ct, kem->length_ciphertext, ct_hex);
    bytes_to_hex(ss, kem->length_shared_secret, ss_hex);

    printf("{\"success\":true,\"algorithm\":\"%s\",\"ciphertextHex\":\"%s\",\"sharedSecretHex\":\"%s\"}\n",
           kem->method_name, ct_hex, ss_hex);

    free(pk); free(ct); free(ss); free(ct_hex); free(ss_hex);
    OQS_KEM_free(kem);
}

static void cmd_kem_decaps(const char *sk_hex, const char *ct_hex) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (!kem) fail("ML-KEM-1024 not available");

    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    hex_to_bytes(sk_hex, sk);
    hex_to_bytes(ct_hex, ct);

    uint8_t *ss = malloc(kem->length_shared_secret);
    if (OQS_KEM_decaps(kem, ss, ct, sk) != OQS_SUCCESS) fail("decapsulation failed");

    char *ss_hex = malloc(kem->length_shared_secret * 2 + 1);
    bytes_to_hex(ss, kem->length_shared_secret, ss_hex);

    printf("{\"success\":true,\"algorithm\":\"%s\",\"sharedSecretHex\":\"%s\"}\n", kem->method_name, ss_hex);

    free(sk); free(ct); free(ss); free(ss_hex);
    OQS_KEM_free(kem);
}

static void cmd_sig_keygen(void) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) fail("ML-DSA-87 not available in this liboqs build");

    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) fail("keygen failed");

    char *pk_hex = malloc(sig->length_public_key * 2 + 1);
    char *sk_hex = malloc(sig->length_secret_key * 2 + 1);
    bytes_to_hex(pk, sig->length_public_key, pk_hex);
    bytes_to_hex(sk, sig->length_secret_key, sk_hex);

    printf("{\"success\":true,\"algorithm\":\"%s\",\"publicKeyHex\":\"%s\",\"secretKeyHex\":\"%s\","
           "\"publicKeyBytes\":%zu,\"secretKeyBytes\":%zu}\n",
           sig->method_name, pk_hex, sk_hex, sig->length_public_key, sig->length_secret_key);

    free(pk); free(sk); free(pk_hex); free(sk_hex);
    OQS_SIG_free(sig);
}

static void cmd_sig_sign(const char *sk_hex, const char *message) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) fail("ML-DSA-87 not available");

    uint8_t *sk = malloc(sig->length_secret_key);
    hex_to_bytes(sk_hex, sk);

    uint8_t *signature = malloc(sig->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(sig, signature, &sig_len, (const uint8_t *)message, strlen(message), sk) != OQS_SUCCESS) {
        fail("signing failed");
    }

    char *sig_hex = malloc(sig_len * 2 + 1);
    bytes_to_hex(signature, sig_len, sig_hex);

    printf("{\"success\":true,\"algorithm\":\"%s\",\"signatureHex\":\"%s\",\"signatureBytes\":%zu}\n",
           sig->method_name, sig_hex, sig_len);

    free(sk); free(signature); free(sig_hex);
    OQS_SIG_free(sig);
}

static void cmd_sig_verify(const char *pk_hex, const char *message, const char *sig_hex) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!sig) fail("ML-DSA-87 not available");

    uint8_t *pk = malloc(sig->length_public_key);
    hex_to_bytes(pk_hex, pk);

    size_t sig_len = strlen(sig_hex) / 2;
    uint8_t *signature = malloc(sig_len);
    hex_to_bytes(sig_hex, signature);

    OQS_STATUS rc = OQS_SIG_verify(sig, (const uint8_t *)message, strlen(message), signature, sig_len, pk);

    printf("{\"success\":true,\"verified\":%s}\n", rc == OQS_SUCCESS ? "true" : "false");

    free(pk); free(signature);
    OQS_SIG_free(sig);
}

int main(int argc, char **argv) {
    OQS_init();

    if (argc < 2) fail("no command given");

    if (strcmp(argv[1], "kem-keygen") == 0) {
        cmd_kem_keygen();
    } else if (strcmp(argv[1], "kem-encaps") == 0 && argc == 3) {
        cmd_kem_encaps(argv[2]);
    } else if (strcmp(argv[1], "kem-decaps") == 0 && argc == 4) {
        cmd_kem_decaps(argv[2], argv[3]);
    } else if (strcmp(argv[1], "sig-keygen") == 0) {
        cmd_sig_keygen();
    } else if (strcmp(argv[1], "sig-sign") == 0 && argc == 4) {
        cmd_sig_sign(argv[2], argv[3]);
    } else if (strcmp(argv[1], "sig-verify") == 0 && argc == 5) {
        cmd_sig_verify(argv[2], argv[3], argv[4]);
    } else {
        fail("unknown command or wrong argument count");
    }

    OQS_destroy();
    return 0;
}
