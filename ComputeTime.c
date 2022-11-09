#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include "pbc/pbc.h"
#include "pbc/pbc_test.h"
#include <openssl/md5.h>

#define N_ATTR 5

pairing_t pairing;
element_t x, y, a, b, r, r2, base, S, R;
element_t exponent, mul_res_Z, add_res_Z, exp_res_Z, hash_res, add_res_G, mul_res_G, exp_res_G, P, inv_res, hash_res_G;

const int n = 1000;
const int N = 200;
int i, j;
int processes;
double t_start, t_finish;

typedef struct TimesGZ_struct
{
    double mul_Z;
    double inv_Z;
    double add_Z;
    double exp_Z;
    double hash;
    double add_G;
    double mul_G;
    double exp_G;
} TimesGZ;

TimesGZ times_GZ;

int main(int argc, char **argv)
{

    pbc_demo_pairing_init(pairing, argc, argv);

    element_init_G1(P, pairing);
    element_init_G1(add_res_G, pairing);
    element_init_G1(mul_res_G, pairing);
    element_init_G1(exp_res_G, pairing);
    element_init_G1(exp_res_Z, pairing);
    element_init_G1(S, pairing);
    element_init_G1(R, pairing);
    element_init_G1(hash_res_G, pairing);

    element_init_G2(y, pairing);

    element_init_GT(r, pairing);
    element_init_GT(r2, pairing);

    element_init_Zr(exponent, pairing);
    element_init_Zr(base, pairing);
    element_init_Zr(hash_res, pairing);
    element_init_Zr(mul_res_Z, pairing);
    element_init_Zr(add_res_Z, pairing);
    element_init_Zr(exp_res_Z, pairing);
    element_init_Zr(a, pairing);
    element_init_Zr(b, pairing);

    element_init_Zr(inv_res, pairing);
    element_init_Zr(x, pairing);
    //存储md5的hex结果
    unsigned char MD5ans[16] = {0};

    // 1 process
    t_start = pbc_get_time();

    double ttotalmul_Z = 0.0;
    double ttotalinv_Z = 0.0;
    double ttotaladd_Z = 0.0;
    double ttotalexp_Z = 0.0;
    double ttotalhash = 0.0;
    double ttotaladd_G = 0.0;
    double ttotalexp_G = 0.0;
    double ttotalmul_G = 0.0;

    double t0, t1;

    element_random(P);
    element_random(a);
    element_random(b);
    element_random(x);
    element_random(y);
    element_random(S);
    element_random(R);
    element_random(exponent);
    element_random(base);

    for (i = 0; i < n; i++)
    {

        // evaluating time for multiplication in Z_p
        t0 = pbc_get_time();
        element_mul(mul_res_Z, a, b); // mul_res_Z = a * b
        t1 = pbc_get_time();
        // element_printf("%B = %B * %B\n\n", mul_res_Z, a, b);
        ttotalmul_Z += t1 - t0;

        // evaluating time for invert in Z_p
        t0 = pbc_get_time();
        element_invert(inv_res, a); // Set 'inv_res' to the inverse of 'a'.
        t1 = pbc_get_time();
        // element_mul(mul_res_Z, inv_res, a);
        // element_printf("%B \n\n", inv_res);
        ttotalinv_Z += t1 - t0;

        // evaluating time for addition in Z_p
        t0 = pbc_get_time();
        element_add(add_res_Z, a, b); // add_res_Z = a + b
        t1 = pbc_get_time();
        ttotaladd_Z += t1 - t0;

        // evaluating time for General hash function
        t0 = pbc_get_time();
        unsigned char *data = "123";
        unsigned char md[16];
        unsigned long n = 3;
        unsigned char *MD5(const unsigned char *data, unsigned long n, unsigned char *md);
        t1 = pbc_get_time();
        ttotalhash += t1 - t0;

        // evaluating time for addition in G
        t0 = pbc_get_time();
        element_add(add_res_G, S, R); // add_res_G = x + y
        t1 = pbc_get_time();
        // element_printf("S = %B\n\n", S);
        // element_printf("R = %B\n\n", R);
        // element_printf("add_res_G = %B\n\n", add_res_G);
        ttotaladd_G += t1 - t0;

        // evaluating time for multiplication in G
        t0 = pbc_get_time();
        element_mul_zn(mul_res_G, P, x); // mul_res_G = x * y
        t1 = pbc_get_time();
        // element_printf("%B = %B * %B\n\n", mul_res_G, P, x);
        ttotalmul_G += t1 - t0;

        // element_printf("x = %B\n", x);
        // element_printf("y = %B\n", y);
        // element_printf("e(x,y) = %B\n", r);
    }

    times_GZ.mul_Z = ttotalmul_Z / n;
    times_GZ.inv_Z = ttotalinv_Z / n;
    times_GZ.add_Z = ttotaladd_Z / n;
    times_GZ.exp_Z = ttotalexp_Z / n;
    times_GZ.hash = ttotalhash / n;
    times_GZ.add_G = ttotaladd_G / n;
    times_GZ.mul_G = ttotalmul_G / n;
    times_GZ.exp_G = ttotalexp_G / n;

    t_finish = pbc_get_time();

    printf("EXECUTION TIME OF CRYPTOGRAPHIC OPERATION\n");
    printf("Tmm: %.7f ms\n", times_GZ.mul_Z * 1000);
    printf("Tinv: %.7f ms\n", times_GZ.inv_Z * 1000);
    printf("Tma: %.7f ms\n", times_GZ.add_Z * 1000);
    printf("Th: %.7f ms\n", times_GZ.hash * 1000);
    printf("Tpa: %.7f ms\n", times_GZ.add_G * 1000);
    printf("Tpm: %.7f ms\n", times_GZ.mul_G * 1000);

    double tmm = times_GZ.mul_Z * 1000;
    double tinv = times_GZ.inv_Z * 1000;
    double tma = times_GZ.add_Z * 1000;
    double th = times_GZ.hash * 1000;
    double tpa = times_GZ.add_G * 1000;
    double tpm = times_GZ.mul_G * 1000;

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

    element_clear(x);
    element_clear(y);
    element_clear(a);
    element_clear(b);
    element_clear(r);
    element_clear(r2);
    element_clear(mul_res_Z);
    element_clear(add_res_Z);
    element_clear(exp_res_Z);
    element_clear(hash_res);
    element_clear(add_res_G);
    element_clear(mul_res_G);
    element_clear(exp_res_G);
    element_clear(exponent);
    element_clear(base);

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