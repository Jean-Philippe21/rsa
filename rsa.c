/**
 * @file rsa.c
 * @brief RSA textbook implementation
 *
 * @author Arnaud ROSAY
 * @date Nov 3, 2021
*/

#define RSA_C

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include "rsa_toolbox.h"
#include "rsa.h"


/**
 * generate a pair of keys of a specific size with different modes
 * @param[in,out] k_pub pointer to the public key to generate
 * @param[in,out] k_pub pointer to the private key to generate
 * @param[in] key_size number of bits (power of 2, from 8 to 64) of the key to generate
 * @param[in] prob probability that the generated number is not a prime number (not used in MODE_NAIVE mode)
 * @param[in] mode supported modes are limited to MODE_NAIVE and MODE_MILLER_RABIN
 * @return prime number
 * @note prob is useful
 */
void rsa_get_keys(rsa_public_key_t *k_pub, rsa_private_key_t *k_priv,
                  uint64_t key_size, double prob, uint64_t mode)
{

    // write your code here
    #if 0
    uint64_t n = key_size;
    uint64_t borne_inf = 0, borne_sup = 0, p = 0, q = 0, N = 0, phi_N = 0, e = 0, d = 0;

    borne_inf = pow(2,(n/2));
    borne_sup = pow(2,((n+1)/2));
    do{
        p = rsa_tbox_get_prime(borne_inf,borne_sup,prob,mode);
        q = rsa_tbox_get_prime(borne_inf,borne_sup,prob,mode);
    }while(p==q);
    N = p*q;
    phi_N = (p-1)*(q-1);
    e = 
    #endif
    




}

/**
 * cipher a value using public key, either in naive mode or using binary exponentiation
 * @param ciphered pointer to the ciphered value
 * @param clear value to cipher
 * @param k_pub public key structure
 * @param mode either MODE_NAIVE (naive exp) or MODE_OPTIMIZED (binary exponentiation)
 */
void rsa_cipher(uint64_t *ciphered, uint64_t clear, rsa_public_key_t k_pub, uint64_t mode)
{
 
    // write your code here
    if(ciphered==NULL){
        fprintf(stderr, "[ERROR] rsa_cipher: bad input parameter\n");
	    exit(EXIT_FAILURE);
    }

    if(mode==MODE_OPTIMIZED){
        *ciphered = rsa_tbox_binary_mod_exp(clear,k_pub.e,k_pub.N);
    }
    if(mode==MODE_NAIVE){
        *ciphered = rsa_tbox_naive_mod_exp(clear,k_pub.e,k_pub.N);
    }
    




}

/**
 * decipher a value using private key
 * @param clear pointer to the deciphered value
 * @param ciphered value to decipher
 * @param k_priv private key structure
 * @param mode either MODE_NAIVE (naive exp) or MODE_OPTIMIZED (binary exponentiation)
 */
void rsa_decipher(uint64_t *clear, uint64_t ciphered, rsa_private_key_t k_priv, uint64_t mode)
{
  
    // write your code here
    if(clear==NULL && k_priv.p!=k_priv.q){
        fprintf(stderr, "[ERROR] rsa_cipher: bad input parameter\n");
	    exit(EXIT_FAILURE);
    }

    if(mode==MODE_OPTIMIZED){
        *clear = rsa_tbox_binary_mod_exp(ciphered,k_priv.d,k_priv.p * k_priv.q);
    }

    if(mode==MODE_NAIVE){
        *clear = rsa_tbox_naive_mod_exp(ciphered,k_priv.d,k_priv.p * k_priv.q);
    }

}

/**
 *
 * @param ciphered1
 * @param k_pub1
 * @param ciphered2
 * @param k_pub2
 * @return
 */
uint64_t rsa_common_modulus_attack(uint64_t ciphered1, rsa_public_key_t k_pub1,
                                   uint64_t ciphered2, rsa_public_key_t k_pub2)
{
    uint64_t m = 0;
 
    // write your code here


    return m;
}

/**
 *
 * @param tab_ciphered
 * @param tab_n
 * @return
 */
uint64_t rsa_Hastad_attack(uint64_t *tab_ciphered, uint64_t *tab_n, uint64_t tab_size)
{
    uint64_t clear_msg = 0, N=1, tab_u[4]={0}, result=0, k = 3;
    uint64_t gcd=0; int64_t u=1; int64_t v=0;
    for (uint64_t i = 0; i < tab_size; i++)
    {
        N = N*tab_n[i];
    }
    for (uint64_t i = 0; i < tab_size; i++)
    {
        rsa_tbox_extended_euclidian(&gcd,&u,&v,(N/tab_n[i]),tab_n[i]);
        if (u<0 &&  v<0)
        {
            u = (1- (tab_n[i]*v))/(N/tab_n[i]);
        }
        
        tab_u[i] = u;
        //printf("\n u = %ld et v = %ld et div = %ld",u,v,(N/tab_n[i]));
    }
    //Processing of M^3
        for (uint64_t i = 0; i < k; i++)
        {
            result += tab_ciphered[i]*tab_u[i]*(N/tab_n[i]);
            
        }
        //printf("\nresult = %ld et N=%ld",result,N);
        result = N%result;
        printf("\nVoici M^%ld = %ld",k,result);

    //Prpcessing of M
       clear_msg = pow(result,(1/(double)k)); 
       printf("\nLe message en clair = %Lf",powl(result,(1/(double)k)));

    return clear_msg;
}

#undef RSA_C
