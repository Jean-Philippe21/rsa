/**
 * @file rsa_toolbox.c
 * @brief RSA tool box implementation
 *
 * @author Arnaud ROSAY
 * @date Nov 3, 2021
*/

#define RSA_TOOLBOX_C

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "rsa_toolbox.h"

/**
 * generate a 64-bit random value between min and max
 * @param[in] min minimum value that can be returned
 * @param[in] max maximum value that can be returned
 * @return random integer number
 */
uint64_t rsa_tbox_get_rand(uint64_t min, uint64_t max) {
    uint64_t r = 0;
    uint64_t loop_count;
    uint64_t val = RAND_MAX >> 8;
    if (val >= 0xFFFFFFFFFFFFFF) {
        loop_count = 1;
    } else if (val >= 0xFFFFFF) {
        loop_count = 2;
    } else if (val >= 0x3FFFF) {
        loop_count = 3;
    } else if (val >= 0x1FF) {
        loop_count = 4;
    } else {
        loop_count = 5;
    }
    for (uint64_t i = loop_count; i > 0; i--) {
        r = r * (RAND_MAX + (uint64_t) 1) + rand();
    }
    r = min + r % (max+1 - min);
    return r;
}

/**
 * generate a prime number of a specific size with different modes
 * @param[in] lower_bound lower bound value of the interval containing the prime to generate
 * @param[in] upper_bound upper bound value of the interval containing the prime to generate
 * @param[in] prob probability that the generated number is not a prime number (not used in MODE_NAIVE mode)
 * @param[in] mode supported modes are limited to MODE_NAIVE and MODE_MILLER_RABIN
 * @return prime number
 */
uint64_t rsa_tbox_get_prime(uint64_t lower_bound, uint64_t upper_bound, double prob, uint64_t mode){
    uint64_t prime = 0;

    // write your code here
    #if 0
    bool fund_primary_number = false;
    
    do{
    	prime =  (lower_bound-rand()) % upper_bound;
    	if(rsa_tbox_primality_test_naive(prime)==1){
    		fund_primary_number=true;
    	}else if(mode==MODE_MILLER_RABIN){
    	}
    	
    }while(!fund_primary_number);
    
    
    //printf("nombre genere : %d\n", prime);
    #endif
    if(mode==MODE_NAIVE){
        uint64_t r=0;
        while (prime==0)
        {
            r = rsa_tbox_get_rand(lower_bound,upper_bound);
            if(rsa_tbox_primality_test_naive(r)==1){
                prime = r;
            }
        }
        
    }

    return prime;
}

/**
 * test primality with a naive method
 * @param val value to test
 * @return 1 if val is a prime number, 0 otherwise
 */
uint64_t rsa_tbox_primality_test_naive(uint64_t val)
{
    uint64_t prime_found = 55;
    int i;
 
    // write your code here
    if(val==1 || val==0)
    {
        //printf("le nombre %ld n'est pas premier",val);
        return 0;
    }
    for(i=2;i<sqrt(val);i++)
    {
      if(val%i==0)
      {	  //printf("le nombre %ld n'est pas premier",val);
          return 0;
      }
    }
          //printf("Le nombre %ld est premier",val);
          prime_found = 1;

    return prime_found;
}

/**
 * calculate the number of value to test in Miller-Rabin primality test to reach a given probability of error
 * @param val prime value to test
 * @param prob probability (order of magnitude) to wrongly declare a composite number as a prime number
 * @return number of values to use
 * @note val is needed as the result depends on the number of bits needed to encode the prime value
 */
uint64_t rsa_tbox_get_n_values_miller_rabin(uint64_t val, double prob)
{
    uint64_t n_val = 0;
    uint64_t nbr_bit_of_val = 0;
    //double temp =0;

    // write your code here
    //Déterminons d'abord le nombre de bit
    nbr_bit_of_val = rsa_tbox_get_size_in_bits(val);

    //n_val = (1/log(4))*log( log(pow(2,nbr_bit_of_val))/ (2*prob) );
    n_val = (1/log(4))*log( log(1L<<nbr_bit_of_val)/ (2*prob) );


    return n_val;
}

/**
 * calculate the number of bit needed to encode the unsigned integer value n
 * @param n unsigned integer
 * @return number of bit
 */
uint64_t rsa_tbox_get_size_in_bits(uint64_t n)
{
    uint64_t n_bits = 0;
    double temp =0;
    // write your code here
    if(n<=0){
        fprintf(stderr, "[ERROR] rsa_tbox_get_size_in_bits: bad input parameter\n");
	    exit(EXIT_FAILURE);
    }
    temp = log(n)/log(2);
    n_bits = temp+1;

    return n_bits;
}

/**
 * calculate modular binary exponentiation using naive method
 * @param[in] b base
 * @param[in] e exponent
 * @param[in] n modulus
 * @return b^e mod n
 */
uint64_t rsa_tbox_naive_mod_exp(uint64_t b, uint64_t e, uint64_t n)
{
    uint64_t result = 1;
    b = b%n;
    if(b==0){
        return 0;
    }
    while(e>0){
        if(e%2==1){
            result = (result*b)%n;
        }
        b = (b*b)%n;
        e=e/2;
    }

    return result;
}

/**
 * calculate modular binary exponentiation using left to right method
 * @param[in] b base
 * @param[in] e exponent
 * @param[in] n modulus
 * @return b^e mod n
 */
uint64_t rsa_tbox_binary_mod_exp(uint64_t b, uint64_t e, uint64_t n)
{
    uint64_t result = 0;
    int i = rsa_tbox_get_size_in_bits(e);
    unsigned bit = (e & (1 << (i-1))) >> (i-1);
    while (bit!=1)
    {
        i = i-1;
        bit = (e & (1 << (i-1) )) >> (i-1);
    }
    i = i-1;
    bit = (e & (1 << (i-1) )) >> (i-1);
    result = b;
    while (i>0)
    {
        result = (result * result)%n;
        if (bit==1)
        {
            result = (result*b)%n;
        }
        i = i-1;
        bit = (e & (1 << (i-1))) >> (i-1);
    }
    
    return result;
}

uint64_t rsa_tbox_primality_test_miller_rabin(uint64_t n, double prob)
{
    uint64_t result = 55;
    uint64_t s=0,d=0,n_val=0,a=0;
    bool test_redondance_a=false;
    uint64_t *tab=NULL;//Tableau pour évité une redondance de a
    if(n<2){
        return COMPOSITE;
    }
    if(n==2){
        return PROBABLY_PRIME;
    }
    if(n!=2 && (n%2==0)){
        return COMPOSITE;
    }
    s=0;
    d=n-1;
    while ((d & 1)==0)
    {
        d = (d >> 1);
        s = s+1;
    }
    //Ya une ligne qui est déjà faite dans la fonction "rsa_tbox_get_n_values_miller_rabin(..,..)"
    n_val = rsa_tbox_get_n_values_miller_rabin(n,prob);
    if (n<n_val+2)
    {
        fprintf(stderr, "[ERROR] rsa_tbox_primality_test_miller_rabin: bad input parameter\n");
	    exit(EXIT_FAILURE);
    }
    tab=malloc(n_val*sizeof(uint64_t));
    if(tab==NULL){
        fprintf(stderr, "[ERROR] rsa_tbox_primality_test_miller_rabin: allocation memory not work\n");
	    exit(EXIT_FAILURE);
    }
    //initialisation des valeurs du tableau à 0
    for (uint64_t i = 0; i < n_val; i++)
    {
        tab[i]=0;
    }
    
    while (n_val!=0)
    {
        a = rsa_tbox_get_rand(2,n-2);
        
        //Pas sûr que le test que je fais marche très bien !!!
        do{
            //printf("\nJe suis la...\n");
            for (uint64_t i = 0; i < n_val; i++)
            {
                if(tab[i]==a){
                    test_redondance_a=true;
                    break;
                }
                    
            }
            if(!test_redondance_a){
                tab[n_val-1]=a;
            }
            
        }while(test_redondance_a);
        
        
        if(rsa_tbox_miller_witness(a,s,d,n)){
            return COMPOSITE;
        }
        n_val--;
    }
    free(tab);

    result = PROBABLY_PRIME;

    return result;
}


/**
 * check whether a is a witness of compositeness of n
 * @param a base value
 * @param s so that n=d.2^s with d odd
 * @param d so that n=d.2^s with d odd
 * @param n value to check as prime or composite
 * @return true if a is a Miller witness, else otherwise
 */
bool rsa_tbox_miller_witness(uint64_t a, uint64_t s, uint64_t d, uint64_t n)
{
    bool is_witness;
    uint64_t b = rsa_tbox_binary_mod_exp(a,d,n);
    if(b!=1 && (b!=n-1) ){
        if(s==1){
            return true;
        }
        for (uint64_t i = 0; i < s-1; i++)
        {
            b = rsa_tbox_binary_mod_exp(b,2,n);
            if(b==1){
                return true;
            }
            if(b==(n-1)){
                return false;
            }
        }
        if(b!=(n-1)){
            return true;
        }
    }
    is_witness = false;

    return is_witness;
}

/**
 * calculate modular inverse using extended Euclidian algorithm
 * @param val
 * @param mod
 * @return
 */
uint64_t rsa_tbox_mod_inverse(uint64_t val, uint64_t mod)
{
    uint64_t inverse = 0;
    uint64_t gcd=0; int64_t u=1; int64_t v=0;
 
    // write your code here
    if(val>=mod){
        fprintf(stderr, "[ERROR] rsa_tbox_mod_inverse: bad input parameter\n");
	    exit(EXIT_FAILURE);
    }
    
    rsa_tbox_extended_euclidian(&gcd,&u,&v,mod,val);

    //printf("\ngcd=%ld,u=%ld,v=%ld\n",gcd,u,v);
    if(u<0 &&  v<0){
        if(u<v){
            inverse = mod + u;
        }else{
            inverse = mod + v;
        }
    }else if(u>0 && v>0  ){
        if(u>v){
            inverse = u;
        }else{
            inverse = v;
        }
    }else if(u>=0 && v<=0){
        inverse = mod+v; // Je suis pas très sur de ce cas
    }else{
        inverse = v;
    }

    return inverse;
}

/**
 * run extended Euclidian algorithm to calculate gcd(a,b) and Bézout's coefficient u, v (a.u+b.v=1)
 * @param[in,out] gcd pointer to the greateset common divisor
 * @param[in,out] u pointer to the first Bézout's coefficient
 * @param[in,out] v pointer to the second Bézout's coefficient
 * @param[in] a pointer to the first input value
 * @param[in] b pointer to the second input value
 * @note condition to respect: a > b
 */
void rsa_tbox_extended_euclidian(uint64_t *gcd, int64_t *u, int64_t *v, uint64_t a, uint64_t b)
{
    int64_t s,t,r,tmp;
    uint64_t temp_a=a,temp_b=b;
    int64_t q;
    //printf("\ngcd=%ln, u=%ln, v=%ln, a=%ld, b=%ld",gcd,u,v,a,b);
    // write your code here
    if(gcd==NULL || u==NULL || v==NULL){
    	fprintf(stderr, "[ERROR] rsa_tbox_extended_euclidian: bad input parameter\n");
	    exit(EXIT_FAILURE);
    }
    if(a>b){
	    *u=1;//in-out
	    *v=0;//in-out
	    s=0;
	    t=1;
	    while(temp_b>0){
            q=(temp_a/temp_b);
            //printf("\nq=%ld",q);
            r=(temp_a%temp_b);
            //printf("\nr=%ld",r);
            temp_a=temp_b;
            temp_b=r;
            tmp=s;
            s=(*u)-(q*r);
            *u=tmp;
            tmp=t;
            t=(*v)-(q*t);
            *v=tmp;
	    }
	    *gcd = temp_a;
	    //printf("\ngcd=%ld,u=%ld,v=%ld\n",*gcd,*u,*v);
	   
    }else{
    	fprintf(stderr, "[ERROR] rsa_tbox_extended_euclidian: bad input parameter\n");
	exit(EXIT_FAILURE);
    }
}

/**
 * Calculate Hamming weight of the given value
 * @param val value used to calculate Hamming weight
 * @return Hamming weight
 */
uint64_t rsa_tbox_hamming_weight(uint64_t val)
{
    uint64_t count;
    for (count=0; val; count++)
        val &= val - 1;
    return count;
}


#undef RSA_TOOLBOX_C
