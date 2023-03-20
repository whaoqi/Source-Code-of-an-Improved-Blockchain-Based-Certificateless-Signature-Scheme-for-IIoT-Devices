#include "pbc/pbc.h"
#include "pbc/pbc_test.h"
#include <openssl/md5.h>

// Number of cycle calculations
#define N_ATTR 1000

// Storage the calculation results for different operation times
typedef struct Times_struct
{
    double mul_Z;
    double inv_Z;
    double add_Z;
    double hash;
    double add_G;
    double mul_G;
} TimesStore;

TimesStore times_Res;

int main(int argc, char **argv)
{
    // Define a paired type variable
    pairing_t pairing;
    pbc_demo_pairing_init(pairing, argc, argv);
    // Define elements of an algebraic structure
    element_t a, b, x, y;
    element_t mul_res_Z, inv_res_Z, add_res_Z, add_res_G, mul_res_G;

    // Initialize the variable to the element in the ring Zr
    element_init_Zr(mul_res_Z, pairing);
    element_init_Zr(inv_res_Z, pairing);
    element_init_Zr(add_res_Z, pairing);
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);

    // Initialize the variable to an element in group G1
    element_init_G1(add_res_G, pairing);
    element_init_G1(mul_res_G, pairing);
    element_init_G1(x, pairing);
    element_init_G1(y, pairing);

    // Randomly select an element of the group or ring and assign it to a variable
    element_random(a);
    element_random(b);
    element_random(x);
    element_random(y);

    // Define start time, end time, total time for each calculation
    double t0, t1;
    double totalmul_Z = 0.0;
    double totalinv_Z = 0.0;
    double totaladd_Z = 0.0;
    double totalhash = 0.0;
    double totaladd_G = 0.0;
    double totalmul_G = 0.0;

    // Repeat the calculation N_ATTR times
    for (int i = 0; i < N_ATTR; i++)
    {

        // evaluating time for multiplication in Z_p
        t0 = pbc_get_time();
        // mul_res_Z = a * b
        element_mul(mul_res_Z, a, b);
        t1 = pbc_get_time();
        // element_printf("%B = %B * %B\n\n", mul_res_Z, a, b);
        totalmul_Z += t1 - t0;

        // evaluating time for invert in Z_p
        t0 = pbc_get_time();
        // Set 'inv_res_Z' to the inverse of 'a'.
        element_invert(inv_res_Z, a);
        t1 = pbc_get_time();
        // element_mul(mul_res_Z, inv_res_Z, a);
        // element_printf("%B \n\n", mul_res_Z);
        totalinv_Z += t1 - t0;

        // evaluating time for addition in Z_p
        t0 = pbc_get_time();
        // add_res_Z = a + b
        element_add(add_res_Z, a, b);
        t1 = pbc_get_time();
        // element_printf("%B = %B + %B\n\n", add_res_Z, a, b);
        totaladd_Z += t1 - t0;

        // evaluating time for General hash function, take MD5 as an example
        t0 = pbc_get_time();
        unsigned char *data = "123";
        unsigned char md[16];
        unsigned long n = 3;
        unsigned char *MD5(const unsigned char *data, unsigned long n, unsigned char *md);
        t1 = pbc_get_time();
        totalhash += t1 - t0;

        // evaluating time for addition in G
        t0 = pbc_get_time();
        // add_res_G = x + y
        element_add(add_res_G, x, y);
        t1 = pbc_get_time();
        // element_printf("%B = %B + %B\n\n", add_res_G, x, y);
        totaladd_G += t1 - t0;

        // evaluating time for multiplication in G
        t0 = pbc_get_time();
        // mul_res_G = x * a
        element_mul_zn(mul_res_G, x, a);
        t1 = pbc_get_time();
        // element_printf("%B = %B * %B\n\n", mul_res_G, x, a);
        totalmul_G += t1 - t0;
    }

    // Divide by total number of times to calculate single time
    times_Res.mul_Z = totalmul_Z / N_ATTR;
    times_Res.inv_Z = totalinv_Z / N_ATTR;
    times_Res.add_Z = totaladd_Z / N_ATTR;
    times_Res.hash = totalhash / N_ATTR;
    times_Res.add_G = totaladd_G / N_ATTR;
    times_Res.mul_G = totalmul_G / N_ATTR;

    double tmm = times_Res.mul_Z * 1000;
    double tinv = times_Res.inv_Z * 1000;
    double tma = times_Res.add_Z * 1000;
    double th = times_Res.hash * 1000;
    double tpa = times_Res.add_G * 1000;
    double tpm = times_Res.mul_G * 1000;

    // Results
    printf("EXECUTION TIME OF CRYPTOGRAPHIC OPERATION\n");
    printf("+------+--------------+\n");
    printf("| Tmm  | %.7f ms |\n", tmm);
    printf("+------+--------------+\n");
    printf("| Tinv | %.7f ms |\n", tinv);
    printf("+------+--------------+\n");
    printf("| Tma  | %.7f ms |\n", tma);
    printf("+------+--------------+\n");
    printf("| Th   | %.7f ms |\n", th);
    printf("+------+--------------+\n");
    printf("| Tpa  | %.7f ms |\n", tpa);
    printf("+------+--------------+\n");
    printf("| Tpm  | %.7f ms |\n", tpm);
    printf("+------+--------------+\n");

    /* we analyze all the above-mentioned schemes regarding the signature generation and verification process,
    then calculate the time cost.*/
    printf("\nIn Gong scheme:\n");
    printf("The time to generate a signature is %.7f ms\n", tpm + 2 * th + 2 * tmm + 2 * tma);
    printf("The time to verify a signature is %.7f ms\n\n", 4 * tpm + 3 * tpa + 3 * th);

    printf("In Jia scheme:\n");
    printf("The time to generate a signature is %.7f ms\n", tpm + 2 * th + 3 * tmm + 2 * tma + tinv);
    printf("The time to verify a signature is %.7f ms\n\n", 4 * tpm + 2 * tpa + 2 * th);

    printf("In Thumbur scheme:\n");
    printf("The time to generate a signature is %.7f ms\n", 2 * tpm + 2 * th + 2 * tmm + 2 * tma);
    printf("The time to verify a signature is %.7f ms\n\n", 3 * tpm + 2 * tpa + 2 * th);

    printf("In Xu scheme:\n");
    printf("The time to generate a signature is %.7f ms\n", tpm + 2 * th + 2 * tmm + 2 * tma);
    printf("The time to verify a signature is %.7f ms\n\n", 4 * tpm + 3 * tpa + 3 * th);

    printf("In Wang scheme:\n");
    printf("The time to generate a signature is %.7f ms\n", tmm + th + tma);
    printf("The time to verify a signature is %.7f ms\n\n", 3 * tpm + 3 * tpa + 3 * th);

    printf("In Xiang scheme:\n");
    printf("The time to generate a signature is %.7f ms\n", tpm + 2 * th + 4 * tmm + tma);
    printf("The time to verify a signature is %.7f ms\n\n", 4 * tpm + 2 * tpa + 3 * th);

    printf("In Our scheme:\n");
    printf("The time to generate a signature is %.7f ms\n", tpm + 2 * th + 2 * tmm + 2 * tma);
    printf("The time to verify a signature is %.7f ms\n\n", 4 * tpm + 3 * tpa + 3 * th);

    // Clear variables and release occupied resources
    element_clear(a);
    element_clear(b);
    element_clear(x);
    element_clear(y);
    element_clear(mul_res_Z);
    element_clear(inv_res_Z);
    element_clear(add_res_Z);
    element_clear(add_res_G);
    element_clear(mul_res_G);
    pairing_clear(pairing);

    return 0;
}

/*
ISTRUZIONI ESECUZIONE FILE:
compilare con comando:
gcc -o bin/ComputeTime ComputeTime.c -L. -lm -lgmp -lpbc
per eseguire nella corrente configurazione:
./bin/ComputeTime
se si vuole eseguire passando i parametri di una determinata curva ellitica presente nella directory "param"
(usando pbc_demo_pairing_init):
./bin/ComputeTime <~/.../pbc-0.5.14/param/<file>.param
*/