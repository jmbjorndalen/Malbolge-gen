#ifndef _MS_UTILS__H__
#define _MS_UTILS__H__

#include <sys/time.h>
#include <stdlib.h>

/* Note: This needs to be compiled with -O2 to avoid having the linker complaint
 * about undefined reference to the function. 
 */ 
#if defined __x86_64__
#define rdtscll(val) do { \
     unsigned int a,d; \
     asm volatile("rdtsc" : "=a" (a), "=d" (d)); \
     (val) = ((unsigned long)a) | (((unsigned long)d)<<32); \
} while(0)

extern inline unsigned long long get_timestamp()
{
	unsigned long long v; 
	rdtscll(v);
	return v;
}
#else
extern inline unsigned long long get_timestamp()
{
    unsigned long long x; 
    asm volatile ("rdtsc;" 
		  "movl %0, %%ecx;"
		  "movl %%eax, 0(%%ecx);" 
		  "movl %%edx, 4(%%ecx);"
		  : : "g" (&x) : "eax", "ecx", "edx");
    return x;
}
#endif

extern inline unsigned long long get_tod_usecs()
{
    struct timeval tod; 
    gettimeofday(&tod, NULL); 
    return ((unsigned long long) tod.tv_sec) * 1000000LL + (unsigned long long) tod.tv_usec; 
}

double processor_frequency(int sample_secs);

/* Integer modulo. 
 * c/c++ uses the "wrong" type of modulo arithmetic. See http://dbforums.com/showthread.php?t=317629
 * in c++    -1 % 94 returns -1, but this may be compiler/architecture dependent! 
 * This function behaves the same way as the python modulo (%) operator. 
 */ 
static inline int imod(int a, int b)
{
    int r = a % b; 
    if (r < 0) 
	return b + r; // (nb: adding negative number)
    else
	return r; 
}

// Return largest of two integers
static inline int imax(int a, int b)
{
    return a > b ? a : b; 
}

// modulo increment
static inline int modInc(int v, int m) { 
    return (v + 1) % m; 
}

double timeSince(long long start)
{
    long long now = get_tod_usecs(); 
    return (now - start) / 1000000.0; 
}

#endif
