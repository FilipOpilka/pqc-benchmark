#define _POSIX_C_SOURCE 199309L

#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <math.h>

#define WARMUP_RUNS 3
#define MEASUREMENT_RUNS 25
#define TOTAL_RUNS (WARMUP_RUNS + MEASUREMENT_RUNS)
#define CONFIDENCE_LEVEL 2.262  // t-value for 95% CI with 9 degrees of freedom (MEASUREMENT_RUNS-1)

// in bytes
#define DATA_SIZE_START 250
#define DATA_SIZE_END   10000
#define DATA_SIZE_STEP  250


typedef struct {
    const char *alg_name;
    size_t msg_len;
    double keygen_mean;
    double keygen_stddev;
    double keygen_ci;
    double sign_mean;
    double sign_stddev;
    double sign_ci;
    double verify_mean;
    double verify_stddev;
    double verify_ci;
} BenchmarkResult;

double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double) ts.tv_sec * 1000.0 + (double) ts.tv_nsec / 1e6;
}

void print_csv_header(FILE *fp) {
    fprintf(fp, "Algorithm,DataSize,"
            "KeygenMean(ms),KeygenStdDev,KeygenCI(ms),"
            "SignMean(ms),SignStdDev,SignCI(ms),"
            "VerifyMean(ms),VerifyStdDev,VerifyCI(ms)\n");
}

void write_result(FILE *fp, const BenchmarkResult *result) {
    fprintf(fp, "%s,%zu,"
            "%.4f,%.4f,%.4f,"
            "%.4f,%.4f,%.4f,"
            "%.4f,%.4f,%.4f\n",
            result->alg_name,
            result->msg_len,
            result->keygen_mean,
            result->keygen_stddev,
            result->keygen_ci,
            result->sign_mean,
            result->sign_stddev,
            result->sign_ci,
            result->verify_mean,
            result->verify_stddev,
            result->verify_ci);
}

double calculate_stddev(const double *times, double mean, size_t n) {
    double sum_sq_diff = 0.0;
    for (size_t i = 0; i < n; i++) {
        sum_sq_diff += pow(times[i] - mean, 2);
    }
    return sqrt(sum_sq_diff / (n - 1));  // Sample standard deviation
}

double calculate_ci(double stddev, size_t n) {
    return CONFIDENCE_LEVEL * (stddev / sqrt(n));
}

void process_measurements(double *times, double *mean, double *stddev, double *ci) {
    double sum = 0.0;
    for (size_t j = WARMUP_RUNS; j < TOTAL_RUNS; j++) {
        sum += times[j];
    }
    *mean = sum / MEASUREMENT_RUNS;
    
    *stddev = calculate_stddev(&times[WARMUP_RUNS], *mean, MEASUREMENT_RUNS);
    *ci = calculate_ci(*stddev, MEASUREMENT_RUNS);
}

void benchmark_algorithm(const char *alg_name, FILE *csv_file) {
    OQS_SIG *sig = OQS_SIG_new(alg_name);
    if (sig == NULL) return;

    BenchmarkResult result;
    result.alg_name = alg_name;
    
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *message = NULL;
    uint8_t *signature = NULL;
    
    // const size_t data_sizes[] = DATA_SIZES;
    
    for (size_t msg_len = DATA_SIZE_START; msg_len <= DATA_SIZE_END; msg_len += DATA_SIZE_STEP) {
        result.msg_len = msg_len;
        
        // Key generation benchmark
        double keygen_times[TOTAL_RUNS];
        for (size_t j = 0; j < TOTAL_RUNS; j++) {
            public_key = malloc(sig->length_public_key);
            secret_key = malloc(sig->length_secret_key);
            
            double start = get_time_ms();
            OQS_STATUS rc = OQS_SIG_keypair(sig, public_key, secret_key);
            keygen_times[j] = get_time_ms() - start;
            
            if (rc != OQS_SUCCESS) {
                fprintf(stderr, "Keygen failed for %s\n", alg_name);
                free(public_key);
                free(secret_key);
                OQS_SIG_free(sig);
                return;
            }
            
            if (j >= WARMUP_RUNS) {
                free(public_key);
                free(secret_key);
            }
        }
        process_measurements(keygen_times, &result.keygen_mean, 
                           &result.keygen_stddev, &result.keygen_ci);

        // Persistent keys for signing/verification
        public_key = malloc(sig->length_public_key);
        secret_key = malloc(sig->length_secret_key);
        OQS_SIG_keypair(sig, public_key, secret_key);

        // Message generation
        message = malloc(result.msg_len);
        OQS_randombytes(message, result.msg_len);

        // Signing benchmark
        double sign_times[TOTAL_RUNS];
        signature = malloc(sig->length_signature);
        size_t sig_len;
        for (size_t j = 0; j < TOTAL_RUNS; j++) {
            double start = get_time_ms();
            OQS_STATUS rc = OQS_SIG_sign(sig, signature, &sig_len, 
                                       message, result.msg_len, secret_key);
            sign_times[j] = get_time_ms() - start;
            
            if (rc != OQS_SUCCESS) {
                fprintf(stderr, "Sign failed for %s\n", alg_name);
                goto cleanup;
            }
        }
        process_measurements(sign_times, &result.sign_mean,
                           &result.sign_stddev, &result.sign_ci);

        // Verification benchmark
        double verify_times[TOTAL_RUNS];
        for (size_t j = 0; j < TOTAL_RUNS; j++) {
            double start = get_time_ms();
            OQS_STATUS rc = OQS_SIG_verify(sig, message, result.msg_len,
                                         signature, sig_len, public_key);
            verify_times[j] = get_time_ms() - start;
            
            if (rc != OQS_SUCCESS) {
                fprintf(stderr, "Verify failed for %s\n", alg_name);
                goto cleanup;
            }
        }
        process_measurements(verify_times, &result.verify_mean,
                           &result.verify_stddev, &result.verify_ci);

        write_result(csv_file, &result);

        cleanup:
        free(message);
        free(signature);
        free(public_key);
        free(secret_key);
    }

    OQS_SIG_free(sig);
}

int main() {
    OQS_init();
    
    FILE *csv_file = fopen("pqc_benchmark.csv", "w");
    if (!csv_file) {
        perror("Failed to open output file");
        return EXIT_FAILURE;
    }
    print_csv_header(csv_file);

    for (size_t i = 0;; i++) {
        const char *alg_name = OQS_SIG_alg_identifier(i);
        if (alg_name == NULL) break;
        
        printf("Benchmarking %s...\n", alg_name);
        benchmark_algorithm(alg_name, csv_file);
    }

    fclose(csv_file);
    OQS_destroy();
    return EXIT_SUCCESS;
}
