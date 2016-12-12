/*
 * in_cksum --
 *	Checksum routine for Internet Protocol family headers (C Version)
 */

static const char __attribute__((unused)) id[] =
      "@(#) $Id: in_cksum.c,v 1.1.1.8 2007/05/09 20:42:05 sachin Exp $";

#include <sys/types.h>

u_short
in_cksum(u_short* addr, int len)
{
    int nleft, sum;
    u_short* w;
    union
    {
        u_short us;
        u_char uc[2];
    } last;
    u_short answer;

    nleft = len;
    sum = 0;
    w = addr;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        last.uc[0] = *(u_char*)w;
        last.uc[1] = 0;
        sum += last.us;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);                 /* add carry */
    answer = ~sum;                      /* truncate to 16 bits */
    return (answer);
}
