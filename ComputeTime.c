#include "pbc/pbc.h"
#include "pbc/pbc_test.h"
#include <openssl/md5.h>

// Number of cycle calculations
#define N_ATTR 1000

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
    pairing_t pairing;
    pbc_demo_pairing_init(pairing, argc, argv);
    // Define elements of an algebraic structure
    element_t a, b, x, y;
    element_t mul_res_Z, inv_res_Z, add_res_Z, add_res_G, mul_res_G;

    element_init_Zr(mul_res_Z, pairing);
    element_init_Zr(inv_res_Z, pairing);
    element_init_Zr(add_res_Z, pairing);
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);

    element_init_G1(add_res_G, pairing);
    element_init_G1(mul_res_G, pairing);
    element_init_G1(x, pairing);
    element_init_G1(y, pairing);

    element_random(a);
    element_random(b);
    element_random(x);
    element_random(y);

    double t0, t1;
    double totalmul_Z = 0.0;
    double totalinv_Z = 0.0;
    double totaladd_Z = 0.0;
    double totalhash = 0.0;
    double totaladd_G = 0.0;
    double totalmul_G = 0.0;

    for (int i = 0; i < N_ATTR; i++)
    {
        t0 = pbc_get_time();
        // mul_res_Z = a * b
        element_mul(mul_res_Z, a, b);
        t1 = pbc_get_time();
        totalmul_Z += t1 - t0;

        // evaluating time for Modular inversion operation in Z_p
        t0 = pbc_get_time();
        // Set 'inv_res_Z' to the inverse of 'a'.
        element_invert(inv_res_Z, a);
        t1 = pbc_get_time();
        totalinv_Z += t1 - t0;

        // evaluating time for Modular addition operation in Z_p
        t0 = pbc_get_time();
        // add_res_Z = a + b
        element_add(add_res_Z, a, b);
        t1 = pbc_get_time();
        totaladd_Z += t1 - t0;

        t0 = pbc_get_time();
        unsigned char *data = "123";
        unsigned char md[16];
        unsigned long n = 3;
        unsigned char *MD5(const unsigned char *data, unsigned long n, unsigned char *md);
        t1 = pbc_get_time();
        totalhash += t1 - t0;

        // evaluating time for Point addition in G
        t0 = pbc_get_time();
        // add_res_G = x + y
        element_add(add_res_G, x, y);
        t1 = pbc_get_time();
        totaladd_G += t1 - t0;

        // evaluating time for Point multiplication in G
        t0 = pbc_get_time();
        // mul_res_G = x * a
        element_mul_zn(mul_res_G, x, a);
        t1 = pbc_get_time();
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

    // Calculate the execution time of each cryptographic operation in Table IV

    printf("                TABLE IV\n");
    printf("EXECUTION TIME OF CRYPTOGRAPHIC OPERATIONS\n");
    printf("+------+--------------+\n");
    printf("| Tmm  |  %.6f ms |\n", tmm);
    printf("+------+--------------+\n");
    printf("| Tinv |  %.6f ms |\n", tinv);
    printf("+------+--------------+\n");
    printf("| Tma  |  %.6f ms |\n", tma);
    printf("+------+--------------+\n");
    printf("| Th   |  %.6f ms |\n", th);
    printf("+------+--------------+\n");
    printf("| Tpa  |  %.6f ms |\n", tpa);
    printf("+------+--------------+\n");
    printf("| Tpm  |  %.6f ms |\n", tpm);
    printf("+------+--------------+\n");

    // Calculate the communication overhead for each CLS scheme in Table V

    // The bit length of an element of G is 320 bits, and the bit length of q is 160 bits.
    int zq = 160;
    int g = 320;
    printf("                TABLE V\n");
    printf("COMPARISON OF COMMUNICATION OVERHEAD\n");
    printf("+------------+----------------------+\n");
    printf("|   Scheme   |   Communication cost |\n");
    printf("+------------+----------------------+\n");
    printf("|    Gong    |        %d bits      |\n", zq + 2 * g);
    printf("+------------+----------------------+\n");
    printf("|    Jia     |        %d bits      |\n", zq + g);
    printf("+------------+----------------------+\n");
    printf("|   Thumbu   |        %d bits      |\n", zq + g);
    printf("+------------+----------------------+\n");
    printf("|     Xu     |        %d bits      |\n", zq + g);
    printf("+------------+----------------------+\n");
    printf("|    Wang    |        %d bits      |\n", zq + g);
    printf("+------------+----------------------+\n");
    printf("|   Xiang    |        %d bits      |\n", zq + g);
    printf("+------------+----------------------+\n");
    printf("|     Our    |        %d bits      |\n", zq + g);
    printf("+------------+----------------------+\n");

    // Calculate the computational overhead for each CLS scheme in Table VI

    /* we analyze all the above-mentioned schemes regarding the signature generation and verification process, then calculate the time cost.*/
    printf("                TABLE VI\n");
    printf("COMPARISON OF THE COMPUTATIONAL COST OF CLS SCHEMES\n");
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|   Scheme   |   Signature generation  |   Signature verification  |\n");
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|    Gong    |        %.6f ms      |        %.6f ms        |\n", tpm + 2 * th + 2 * tmm + 2 * tma, 4 * tpm + 3 * tpa + 3 * th);
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|    Jia     |        %.6f ms      |        %.6f ms        |\n", tpm + 2 * th + 3 * tmm + 2 * tma + tinv, 4 * tpm + 2 * tpa + 2 * th);
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|   Thumbu   |        %.6f ms      |        %.6f ms        |\n", 2 * tpm + 2 * th + 2 * tmm + 2 * tma, 3 * tpm + 2 * tpa + 2 * th);
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|     Xu     |        %.6f ms      |        %.6f ms        |\n", tpm + 2 * th + 2 * tmm + 2 * tma, 4 * tpm + 3 * tpa + 3 * th);
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|    Wang    |        %.6f ms      |        %.6f ms        |\n", tmm + th + tma, 3 * tpm + 3 * tpa + 3 * th);
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|   Xiang    |        %.6f ms      |        %.6f ms        |\n", tpm + 2 * th + 4 * tmm + tma, 4 * tpm + 2 * tpa + 3 * th);
    printf("+------------+-------------------------+---------------------------+\n");
    printf("|     Our    |        %.6f ms      |        %.6f ms        |\n", tpm + 2 * th + 2 * tmm + 2 * tma, 4 * tpm + 3 * tpa + 3 * th);
    printf("+------------+-------------------------+---------------------------+\n");

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
