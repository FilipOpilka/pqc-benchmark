#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

#define MAX_MESSAGE_SIZE 1048576  // 1MB
#define MESSAGE_SIZE_STEPS 10    // 10 different sizes
#define ITERATIONS 100           // Number of iterations per test

void benchmark_signature(const char *alg_name) {
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) {
        fprintf(stderr, "Algorithm not supported: %s\n", alg_name);
        return;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *secret_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    uint8_t *message = malloc(MAX_MESSAGE_SIZE);

    if (!public_key || !secret_key || !signature || !message) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    printf("Benchmarking: %s\n", alg_name);
    for (int size_step = 0; size_step < MESSAGE_SIZE_STEPS; ++size_step) {
        size_t msg_len = 1 << size_step;  // 1B to 512KB
        if (msg_len > MAX_MESSAGE_SIZE) msg_len = MAX_MESSAGE_SIZE;
        memset(message, 'A', msg_len);

        clock_t start, end;
        double keygen_time = 0, sign_time = 0, verify_time = 0;

        for (int i = 0; i < ITERATIONS; i++) {
            size_t sig_len;

            start = clock();
            OQS_SIG_keypair(sig, public_key, secret_key);
            end = clock();
            keygen_time += ((double)(end - start)) / CLOCKS_PER_SEC;

            start = clock();
            OQS_SIG_sign(sig, signature, &sig_len, message, msg_len, secret_key);
            end = clock();
            sign_time += ((double)(end - start)) / CLOCKS_PER_SEC;

            start = clock();
            OQS_SIG_verify(sig, message, msg_len, signature, sig_len, public_key);
            end = clock();
            verify_time += ((double)(end - start)) / CLOCKS_PER_SEC;
        }

        printf("Size: %6zu bytes | KeyGen: %8.4f ms | Sign: %8.4f ms | Verify: %8.4f ms\n",
               msg_len,
               (keygen_time / ITERATIONS) * 1000,
               (sign_time / ITERATIONS) * 1000,
               (verify_time / ITERATIONS) * 1000);
    }

cleanup:
    free(public_key);
    free(secret_key);
    free(signature);
    free(message);
    OQS_SIG_free(sig);
}

int main() {
    for (size_t i = 0; i < OQS_SIG_alg_count(); i++) {
        const char *alg_name = OQS_SIG_alg_identifier(i);
        benchmark_signature(alg_name);
        printf("\n");
    }
    return 0;
}
