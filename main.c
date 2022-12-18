/**
 * @file main.c
 *
 * @brief main program
 *
 * @author Arnaud ROSAY
 * @date Sep 16, 2021
*/

#define MAIN_C

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include "rsa_toolbox.h"
#include "rsa.h"

/* Global variables */


/* prototypes */
void int_handler(int32_t sig);
uint64_t get_timestamp_nsec(void);
/* part1 */
void part1(void);
void test_prime_number_generator_naive(void);
void test_mod_inverse(void);
void test_mod_exp_naive(void);
void test_rsa_cipher_decipher_naive(void);
/* part2 */
void part2(void);
void test_primality_miller_rabin(void);
void test_gen_keys(void);
void test_perf_prime_number_generator(void);
void test_mod_exp(void);
void test_perf_rsa_cipher_decipher(void);
/* part3 */
void part3(void);
/* part4 */
void part4(void);

/* functions */
/**
 * @brief Exit properly program in case of CTRL-C
 * @param[in] sig interrupt signal, CTRL-C
 */
void int_handler(int32_t sig)
{
    signal(sig, SIG_IGN);
    printf("Program terminated by Ctrl-C\n");
    exit(EXIT_SUCCESS);
}

/**
 * @brief Provide a timestamp in ns
 * @return timestamp value in ns
 */
uint64_t get_timestamp_nsec(void)
{
    uint64_t timestamp_nsec;
    struct timespec timestamp;
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    timestamp_nsec = (uint64_t)timestamp.tv_sec * (uint64_t)1e9;
    timestamp_nsec += (uint64_t)timestamp.tv_nsec;
    return timestamp_nsec;
}

/**
 * @brief test prime number generation in naive mode
 */
void test_prime_number_generator_naive(void)
{
    printf("test of prime number generator in naive mode\n");
    uint64_t prime;
    uint64_t lower_bound, upper_bound;
    double prob = 0.001;
    lower_bound = 0;
    upper_bound = 0xff;
    uint64_t t_start, t_stop;
    uint64_t duration;
    t_start = get_timestamp_nsec();
    prime = rsa_tbox_get_prime(lower_bound, upper_bound, prob, MODE_NAIVE);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("8-bit prime: %lu - duration in naive mode: %lu ns\n", prime, duration);
}

/**
 * @brief test modular inverse with extended Euclidian algorithm
 */
void test_mod_inverse(void)
{
    uint64_t inverse;
    uint64_t val, mod;
    val = 5;
    mod = 26;
    inverse = rsa_tbox_mod_inverse(val, mod);
    printf("Inverse of %lu mod %lu = %lu\n", val, mod, inverse);
    val = 15;
    mod = 26;
    inverse = rsa_tbox_mod_inverse(val, mod);
    printf("Inverse of %lu mod %lu = %lu\n", val, mod, inverse);
    val = 25;
    mod = 26;
    inverse = rsa_tbox_mod_inverse(val, mod);
    printf("Inverse of %lu mod %lu = %lu\n", val, mod, inverse);
    val = 7;
    mod = 160;
    inverse = rsa_tbox_mod_inverse(val, mod);
    printf("Inverse of %lu mod %lu = %lu\n", val, mod, inverse);
}

/**
 * @brief test modular exponentiation in naive mode
 */
void test_mod_exp_naive(void)
{
    uint64_t result, tmp1;
    uint64_t t_start, t_stop;
    uint64_t duration;
    uint64_t b, n, e;

    /* Calculate 157^17 mod 533280 */
    b = 157;
    e = 17;
    n = 533280;
    /*b = 357;
    e = 17;
    n = 533280;*/
    t_start = get_timestamp_nsec();
    result = rsa_tbox_naive_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("%lu^%lu mod %lu = %lu - duration with naive method: %lu ns\n", b, e, n, result, duration);

    /* Calculate 157^257 mod 533280 */
    b = 157;
    e = 257;
    n = 533280;
    /*b = 357;
    e = 257;
    n = 533280;*/
    t_start = get_timestamp_nsec();
    result = rsa_tbox_naive_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("%lu^%lu mod %lu = %lu - duration with naive method: %lu ns\n", b, e, n, result, duration);

    /* Calculate 157^65537 mod 533280 */
    b = 157;
    e = 65537;
    n = 533280;
    /*b = 357;
    e = 65537;
    n = 533280;*/
    t_start = get_timestamp_nsec();
    result = rsa_tbox_naive_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("%lu^%lu mod %lu = %lu - duration with naive method: %lu ns\n", b, e, n, result, duration);

    /* Calculate 157^372833 mod 533280 */
    b = 157;
    e = 372833;
    n = 533280;
    /*b = 357;
    e = 372833;
    n = 533280;*/
    /* trick : call twice naive and binary exp to avoid cache effects */
    tmp1 = rsa_tbox_naive_mod_exp(b, e, n);
    t_start = get_timestamp_nsec();
    result = rsa_tbox_naive_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    if (tmp1 != result) {
        fprintf(stderr, "[ERROR] test_mod_exp_naive\n");
    }
    printf("%lu^%lu mod %lu = %lu - duration with naive method: %lu ns\n", b, e, n, result, duration);
}

/**
 * @brief test RSA ciphering and deciphering in naive mode
 */
void test_rsa_cipher_decipher_naive(void)
{
    /* cipher m=157 with (N, e)=(534749, 65537) and decipher with (p,q,d)=(809, 661, 372833) */
    uint64_t clear_val = 357;
    uint64_t ciphered_val = 0;
    uint64_t deciphered_val = 0;
    rsa_public_key_t k_pub;
    rsa_private_key_t k_priv;
    k_pub.N = 534749;
    k_pub.e = 65537;
    k_priv.p = 809;
    k_priv.q = 661;
    k_priv.d = 372833;
    printf("Clear value = %lu\n", clear_val);
    rsa_cipher(&ciphered_val, clear_val, k_pub, MODE_NAIVE);
    printf("Ciphered value = %lu\n", ciphered_val);
    rsa_decipher(&deciphered_val, ciphered_val, k_priv, MODE_NAIVE);
    printf("Deciphered value = %lu\n", deciphered_val);
}



/**
 * @brief function corresponding to TP-RSA Part1
 */
void part1(void)
{
    //printf("\t le retour : %ld \n",rsa_tbox_primality_test_naive(561));
    //uint64_t gcd=0; int64_t u=1; int64_t v=0;
    //rsa_tbox_extended_euclidian(&gcd,&u,&v,160,23);
    /* Prime number generation in naive mode */
    test_prime_number_generator_naive();
    printf("-----------------------------------------\n");

    /* modular inverse calculation */
    printf("modular inverse calculation\n");
    test_mod_inverse();
    printf("-----------------------------------------\n");

    /* modular exponentiation */
    printf("modular exponentiation calculation\n");
    test_mod_exp_naive();/*
    printf("\ncalcul 1 %ld",rsa_tbox_naive_mod_exp(357, 17, 533280));
    printf("\ncalcul 2 %ld",rsa_tbox_naive_mod_exp(357, 257, 533280));
    printf("\ncalcul 3 %ld",rsa_tbox_naive_mod_exp(357, 65537, 533280));
    printf("\ncalcul 4 %ld",rsa_tbox_naive_mod_exp(357, 372833, 533280));*/
    printf("-----------------------------------------\n");
    //rsa_tbox_get_size_in_bits(15);

    /* RSA cipher/decipher */
    printf("RSA cipher/decipher\n");
    test_rsa_cipher_decipher_naive();
}

/**
 * @brief test modular exponentiation with binary exponentiation
 */
void test_mod_exp(void)
{
    uint64_t result;
    uint64_t t_start, t_stop;
    uint64_t duration;
    uint64_t b, n, e;

    /* Calculate 157^17 mod 533280 */
    b = 157;
    e = 17;
    n = 533280;
    /*b = 357;
    e = 17;
    n = 533280;*/
    rsa_tbox_binary_mod_exp(b, e, n);
    t_start = get_timestamp_nsec();
    result = rsa_tbox_binary_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("%lu^%lu mod %lu = %lu - duration with binary exponentiation method: %lu ns\n", b, e, n, result, duration);

    /* Calculate 157^257 mod 533280 */
    b = 157;
    e = 257;
    n = 533280;
    /*b = 357;
    e = 257;
    n = 533280;*/
    t_start = get_timestamp_nsec();
    result = rsa_tbox_binary_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("%lu^%lu mod %lu = %lu - duration with binary exponentiation method: %lu ns\n", b, e, n, result, duration);

    /* Calculate 157^65537 mod 533280 */
    b = 157;
    e = 65537;
    n = 533280;
    /*b = 357;
    e = 65537;
    n = 533280;*/
    t_start = get_timestamp_nsec();
    result = rsa_tbox_binary_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("%lu^%lu mod %lu = %lu - duration with binary exponentiation method: %lu ns\n", b, e, n, result, duration);

    /* Calculate 157^372833) mod 533280 */
    b = 157;
    e = 372833;
    n = 533280;
    /*b = 357;
    e = 372833;
    n = 533280;*/
    t_start = get_timestamp_nsec();
    result = rsa_tbox_binary_mod_exp(b, e, n);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("%lu^%lu mod %lu = %lu - duration with binary exponentiation method: %lu ns\n", b, e, n, result, duration);
}

/**
 * @brief basic test of Miller-Rabin primality test
 */
void test_primality_miller_rabin(void)
{
    uint64_t val;
    double prob = 0.001;
    uint64_t prime_found;

    /* Miller-Rabin basic test */
    val = 17;
    prime_found = rsa_tbox_primality_test_miller_rabin(val, prob);
    if (prime_found == 1) {
        printf("17 is a prime number\n");
    } else {
        printf("Error in Miller-Rabin primality test\n");
    }
    //printf("\n ********* Voici le retour : %ld \n",rsa_tbox_primality_test_miller_rabin(15, prob));
    val = 659;
    prime_found = rsa_tbox_primality_test_miller_rabin(val, prob);
    if (prime_found == 1) {
        printf("659 is a prime number\n");
    } else {
        printf("Error in Miller-Rabin primality test\n");
    }
    val = 2147483437;
    prime_found = rsa_tbox_primality_test_miller_rabin(val, prob);
    if (prime_found == 0) {
        printf("2147483437 is not a prime number\n");
    } else {
        printf("Error in Miller-Rabin primality test\n");
    }
    val = 4294967291;
    prime_found = rsa_tbox_primality_test_miller_rabin(val, prob);
    if (prime_found == 1) {
        printf("4294967291 is a prime number\n");
    } else {
        printf("Error in Miller-Rabin primality test\n");
    }
}

/**
 * @brief measure performance of prime number generation naive mode vs Miller-Rabin
 */
void test_perf_prime_number_generator(void)
{
    uint64_t prime_8bits, prime_16bits, prime_32bits;
    double prob = 0.001;
    uint64_t t_start, t_stop;
    uint64_t duration;

    /* generate prime number of 8 bits */
    t_start = get_timestamp_nsec();
    prime_8bits = rsa_tbox_get_prime(0x80, 0xff, prob, MODE_NAIVE);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("8-bit prime: %lu - duration in naive mode: %lu\n", prime_8bits, duration);
    t_start = get_timestamp_nsec();
    prime_8bits = rsa_tbox_get_prime(0x80, 0xff, prob, MODE_MILLER_RABIN);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("8-bit prime: %lu - duration in Miller-Rabin mode: %lu\n", prime_8bits, duration);

    /* generate prime number of 16 bits */
    t_start = get_timestamp_nsec();
    prime_16bits = rsa_tbox_get_prime(0x8000, 0xffff, prob, MODE_NAIVE);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("\n16-bit prime: %lu - duration in naive mode: %lu\n", prime_16bits, duration);
    t_start = get_timestamp_nsec();
    prime_16bits = rsa_tbox_get_prime(0x8000, 0xffff, prob, MODE_MILLER_RABIN);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("16-bit prime: %lu - duration in Miller-Rabin mode: %lu\n", prime_16bits, duration);

    /* generate prime number of 32 bits */
    t_start = get_timestamp_nsec();
    prime_32bits = rsa_tbox_get_prime(0x80000000, 0xffffffff, prob, MODE_NAIVE);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("\n32-bit prime: %lu - duration in naive mode: %lu\n", prime_32bits, duration);
    t_start = get_timestamp_nsec();
    prime_32bits = rsa_tbox_get_prime(0x80000000, 0xffffffff, prob, MODE_MILLER_RABIN);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("32-bit prime: %lu - duration in Miller-Rabin mode: %lu\n", prime_32bits, duration);

}

void test_gen_keys(void)
{
    rsa_public_key_t k_pub;
    rsa_private_key_t k_priv;
    uint64_t key_size;
    double prob;
    uint64_t mode;
    uint64_t t_start, t_stop;
    uint64_t duration;

    k_pub.N = 0;
    k_pub.e = 0;
    k_priv.p = 0;
    k_priv.q = 0;
    k_priv.d = 0;

    key_size = 64;
    prob = 0.001;
    mode = MODE_MILLER_RABIN;
    t_start = get_timestamp_nsec();
    rsa_get_keys(&k_pub, &k_priv, key_size, prob, mode);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("k_priv.p = %lu\n", k_priv.p);
    printf("k_priv.q = %lu\n", k_priv.q);
    printf("k_priv.d= %lu\n", k_priv.d);
    printf("k_pub.N = %lu\n", k_pub.N);
    printf("k_pub.e = %lu\n", k_pub.e);
    printf("Duration for %lu bits RSA key generation (Miller-Rabin:) %lu\n", key_size, duration);

    key_size = 64;
    prob = 0.001;
    mode = MODE_NAIVE;
    t_start = get_timestamp_nsec();
    rsa_get_keys(&k_pub, &k_priv, key_size, prob, mode);
    t_stop = get_timestamp_nsec();
    duration = t_stop - t_start;
    printf("k_priv.p = %lu\n", k_priv.p);
    printf("k_priv.q = %lu\n", k_priv.q);
    printf("k_priv.d= %lu\n", k_priv.d);
    printf("k_pub.N = %lu\n", k_pub.N);
    printf("k_pub.e = %lu\n", k_pub.e);
    printf("Duration for %lu bits RSA key generation (naive): %lu\n", key_size, duration);
}

/**
 * @brief test RSA ciphering/deciphering using binary exponentiation with various message and various key length
 */
void test_perf_rsa_cipher_decipher(void)
{
    /* cipher m=357 with (N, e)=(534749, 65537) and decipher with (p,q,d)=(809, 661, 372833) */
    uint64_t clear_val = 357;
    uint64_t ciphered_val = 0;
    uint64_t deciphered_val = 0;
    rsa_public_key_t k_pub;
    rsa_private_key_t k_priv;
    k_pub.N = 534749;
    k_pub.e = 65537;
    k_priv.p = 809;
    k_priv.q = 661;
    k_priv.d = 372833;
    printf("Clear value = %lu\n", clear_val);
    rsa_cipher(&ciphered_val, clear_val, k_pub, MODE_OPTIMIZED);
    printf("Ciphered value = %lu\n", ciphered_val);
    rsa_decipher(&deciphered_val, ciphered_val, k_priv, MODE_OPTIMIZED);
    printf("Deciphered value = %lu\n", deciphered_val);
}

/**
 * @brief function corresponding to TP-RSA Part2
 */
void part2(void)
{
    uint64_t n_values;
    double prob = 0.001;
    uint64_t prime;

    /* Perf comparison of modular exponentiation */
    printf("Perf comparison of modular exponentiation\n");
    test_mod_exp();
    printf("-----------------------------------------\n");

    /* Miller-Rabin - number of values of test */
    printf("Miller-Rabin - number of values of test\n");
    prime = 0xffffffff;
    n_values = rsa_tbox_get_n_values_miller_rabin(prime, prob);
    printf("To reach ~0.001, Rabin-Miller test should use %lu values for a prime of %lu bits\n",
           n_values, rsa_tbox_get_size_in_bits(prime));
    prime = 0xfffffffff;
    n_values = rsa_tbox_get_n_values_miller_rabin(prime, prob);
    printf("To reach ~0.001, Rabin-Miller test should use %lu values for a prime of %lu bits\n",
           n_values, rsa_tbox_get_size_in_bits(prime));
    printf("-----------------------------------------\n");

    /* Miller-Rabin - basic primality test */
    printf("Miller-Rabin - basic primality test\n");
    test_primality_miller_rabin();
    printf("-----------------------------------------\n");
    
    /* Perf comparison of prime number generation */
    printf("Perf comparison of prime number generation\n");
    test_perf_prime_number_generator();
    printf("-----------------------------------------\n");

    /* Perf comparison of RSA key generation */
    printf("Perf comparison of RSA key generation\n");
    test_gen_keys();
    printf("-----------------------------------------\n");


    /* Perf comparison of RSA cipher/decipher */
    printf("Perf comparison of RSA cipher/decipher\n");
    test_perf_rsa_cipher_decipher();
}

/**
* @brief function corresponding to TP-RSA Part3
*/
void part3(void)
{
    rsa_public_key_t k_pub1, k_pub2;
    uint64_t c1, c2, m;

    k_pub1.N = 221;
    k_pub1.e = 11;
    k_pub2.N = k_pub1.N;
    k_pub2.e = 7;
    c1 = 210;
    c2 = 58;

    m = rsa_common_modulus_attack(c1, k_pub1, c2, k_pub2);
    printf("Message in clear is: %lu\n", m);
    printf("Roger's offer should be at least %lu K€\n", m+1);
}

/**
* @brief function corresponding to TP-RSA Part4
*/
void part4(void)
{
 
    // write your code here
    uint64_t tab_ciphered[4]={53,51,124,259}, tab_n[4]={85,69,451,329}, tab_size=4;
    uint64_t clear_msg = 0;

    clear_msg  = rsa_Hastad_attack(tab_ciphered,tab_n,tab_size);

    


}

/**
 * @brief Main process
 * @return 0 when process terminated
 */
int main(void)
{
    /* install int handler to catch Ctrl-C */
    signal(SIGINT, int_handler);
    /* TP is divided in 4 parts */
    printf("=========================================\n");
    printf(" Part 1\n");
    printf("-----------------------------------------\n");
    part1();
    printf("=========================================\n");
    printf(" Part 2\n");
    printf("-----------------------------------------\n");
    part2();
    printf("=========================================\n");
    printf(" Part 3\n");
    printf("-----------------------------------------\n");
    part3();
    printf("=========================================\n");
    printf(" Part 4\n");
    printf("-----------------------------------------\n");
    part4();
    return(0);
}

#undef MAIN_C
