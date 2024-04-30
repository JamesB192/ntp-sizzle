#include <stdint.h>
#include <sys/time.h>
#include <time.h>

int dumbslew(int64_t s, int32_t us);
int dumbstep(int64_t s, int32_t ns);
int64_t ntpcal_ntp_to_time(uint32_t ntp, int64_t pivot);

// Client utility functions

int dumbslew(int64_t s, int32_t us) {
    struct timeval step = {s, us};
    return adjtime(&step, NULL);
}

int dumbstep(int64_t s, int32_t us) {
    struct timeval step = {s, us};
    return settimeofday(&step, NULL);
}

/* Convert a timestamp in NTP scale to a 64bit seconds value in the UN*X
 * scale with proper epoch unfolding around a given pivot or the current
 * system time. This function happily accepts negative pivot values as
 * timestamps before 1970-01-01, so be aware of possible trouble on
 * platforms with 32bit 'time_t'!
 *
 * This is also a periodic extension, but since the cycle is 2^32 and
 * the shift is 2^31, we can do some *very* fast math without explicit
 * divisions.
 */
int64_t ntpcal_ntp_to_time(uint32_t ntp, int64_t pivot) {
    uint64_t res;

    res  = (uint64_t)pivot;
    res  = res - 0x80000000;                 // unshift of half range
    ntp	-= (uint32_t)2208988800;             // warp into UN*X domain
    ntp	-= (uint32_t)((res) & 0xffffffffUL); // cycle difference
    res  = res + (uint64_t)ntp;              // get expanded time

    return res;
}
