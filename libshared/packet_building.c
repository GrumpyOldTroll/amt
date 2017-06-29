
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include "mld6.h"  // copied from freebsd 11.0
#include "igmp.h"  // copied from freebsd, linux doesn't have v3 in 2017


const char*
sock_ntop(int family, void* sa, char* str, int len)
{
    uint16_t port;
    void* addr;
    switch (family) {
        case AF_INET:
        {
            struct sockaddr_in* sin = (struct sockaddr_in*)sa;
            addr = &sin->sin_addr;
            port = htons(sin->sin_port);
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6* sin = (struct sockaddr_in6*)sa;
            addr = &sin->sin6_addr;
            port = htons(sin->sin6_port);
            break;
        }
        default:
            // assert(family == AF_INET || family == AF_INET6);
            snprintf(str, len, "bad family %d in sock_ntop", len);
            return str;
    }

    const char* addr_str = inet_ntop(family, addr, str, len);
    if (!addr_str) {
        return 0;
    }

    int addr_len = strlen(addr_str);
    char* str_tail = str + addr_len;
    snprintf(str_tail, len-addr_len, "(%u)", port);
    return str;
}

uint16_t
iov_csum(struct iovec* iov, unsigned int iov_len)
{
    unsigned int iov_idx;
    unsigned long sum = 0;
    unsigned int odd_byte = 0;
    union {
        uint16_t us;
        uint8_t uc[2];
    } edges;
    for (iov_idx = 0; iov_idx < iov_len; ++iov_idx) {
        unsigned int n_left = iov[iov_idx].iov_len;
        const uint8_t *cur_data = (const uint8_t*)iov[iov_idx].iov_base;
        if (odd_byte) {
            edges.uc[0] = 0;
            edges.uc[1] = *cur_data;
            sum += edges.us;
            n_left -= 1;
            cur_data += 1;
        }
        while (n_left > 1) {
            sum += *((const uint16_t*)cur_data);
            cur_data += 2;
            n_left -= 2;
        }
        if (n_left > 0) {
            edges.uc[0] = *cur_data;
            edges.uc[1] = 0;
            sum += edges.us;
            odd_byte = 1;
        } else {
            odd_byte = 0;
        }
    }
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    uint16_t final = (uint16_t)(~sum);
    return final;
}

uint16_t
csum(uint8_t* buf, unsigned int len)
{
    struct iovec iovecs[1];
    iovecs[0].iov_base = buf;
    iovecs[0].iov_len = len;
    return iov_csum(&iovecs[0], 1);
}


int
build_membership_query(int family, struct sockaddr* source,
        uint8_t* cp, unsigned int len)
{
    switch(family) {
        case AF_INET:
        {
            if (len < sizeof(struct ip) + sizeof(struct igmpv3)) {
                char buf[MAX_SOCK_STRLEN];
                fprintf(stderr, "amtgw internal error: could not build "
                        "IGMP query in %u bytes from %s\n",
                        len, sock_ntop(family, source, buf, sizeof(buf)));
                return -1;
            }
            struct ip* iph;
            struct igmpv3* igmpq;
            struct sockaddr_in* src_addr;
            iph = (struct ip*)cp;
            /* Fill IP header */
            iph->ip_hl = 5;
            iph->ip_v = 4;
            iph->ip_tos = 0;
            iph->ip_len =
                  htons(sizeof(struct ip) + sizeof(struct igmpv3));
            iph->ip_id = htons(random());
            iph->ip_off = 0;
            iph->ip_ttl = 1;
            iph->ip_p = 2; /* IPPROTO_IGMP is 2*/
            iph->ip_sum = 0;
            src_addr = (struct sockaddr_in*)source;
            iph->ip_src = src_addr->sin_addr;
            // iph->ip_dst.s_addr = IGMP_ALL_HOSTS;
            // iph->ip_dst.s_addr = htonl(0xe0000001);
            inet_pton(AF_INET, "224.0.0.1", &iph->ip_dst);

            /* IGMPv3 membership query */
            // https://tools.ietf.org/html/rfc3376#section-4.1
            igmpq = (struct igmpv3*)(cp + sizeof(struct ip));
            igmpq->igmp_type = IGMP_HOST_MEMBERSHIP_QUERY;
            // igmpq->igmp_code = 100;
            igmpq->igmp_code = 16;  // 1.6s response time, instead of 10s (match cisco)
            igmpq->igmp_cksum = 0;
            igmpq->igmp_group.s_addr = 0;
            // igmpq->igmp_misc = (1 << 3); // suppress=1
            // igmpq->igmp_misc = 0; // (cisco doesn't do suppress=1)
            igmpq->igmp_misc = 2; // no suppress, plus set qrv to 2
            igmpq->igmp_qqi = 20; // sending query every 20 seconds

            // TBD: filter by sources? useful if there's multiple gateways
            // running, proxying different source ips.
            igmpq->igmp_numsrc = 0;
            // igmpq->srcs[0] = 0;
            igmpq->igmp_cksum = csum((uint8_t*)igmpq,
                               sizeof(struct igmpv3));
            iph->ip_sum = csum((uint8_t*)iph, sizeof(struct ip));
            len = sizeof(struct ip) + sizeof(struct igmpv3);
            return len;
        }
        break;
        case AF_INET6:
        {
            struct ip6_hdr* iph;
            struct mldv2_query* mld_query_hdr;
            struct ip6_pseudo_ {
                struct in6_addr src;
                struct in6_addr dst;
                uint32_t uplen;
                uint8_t zero[3];
                uint8_t nxthdr;
            } pseudo_hdr;
            struct sockaddr_in6* src_addr;
            u_int8_t r_alert[8] = { IPPROTO_ICMPV6, 0, IP6OPT_ROUTER_ALERT,
                2, 0, 0, IP6OPT_PADN, 0 };

            if (len < sizeof(struct ip6_hdr) + sizeof(struct mldv2_query) +
                    sizeof(r_alert)) {
                char buf[MAX_SOCK_STRLEN];
                fprintf(stderr, "amtgw internal error: could not build "
                        "MLD query in %u bytes from %s\n",
                        len, sock_ntop(family, source, buf, sizeof(buf)));
                return -1;
            }
            iph = (struct ip6_hdr*)cp;
            bzero(cp, sizeof(*iph));
            iph->ip6_vfc = (6 << 4);
#define NEXTHDR_HOP 0
            iph->ip6_nxt = NEXTHDR_HOP;
            iph->ip6_hlim = 1;
            src_addr = (struct sockaddr_in6*)source;
            bcopy(&src_addr->sin6_addr, &iph->ip6_src,
                    sizeof(iph->ip6_src));
            inet_pton(AF_INET6, "ff02::1", &iph->ip6_dst);
            bcopy(r_alert, cp + sizeof(*iph), sizeof(r_alert));

            cp += (sizeof(*iph) + sizeof(r_alert));
            mld_query_hdr = (struct mldv2_query*)cp;
            bzero(mld_query_hdr, sizeof(*mld_query_hdr));
            mld_query_hdr->mld_icmp6_hdr.icmp6_type = 130;

            // MLD_V2_GENERAL_QUERY is 1 because why?
            // regardless, 130 is the value that goes here.
            // https://tools.ietf.org/html/rfc3810#section-5.1
            // mld_query_hdr->mld_icmp6_hdr.icmp6_type = MLD_V2_GENERAL_QUERY;
            // mld_query_hdr->mld_icmp6_hdr.icmp6_type = MLD_LISTENER_QUERY;
            
            // maximum response code = 100 milliseconds
            mld_query_hdr->mld_icmp6_hdr.icmp6_dataun.icmp6_un_data16[0] = htons(100);
            mld_query_hdr->mld_misc = (1 << 3);  // S-bit set
            // leave bottom 3 bits qrv as 0 (default robustness value)
            // mld_query_hdr->mld2q_suppress = 1;
            // leave mld_query_hdr->mld_addr as 0 (unspecified addr)
            mld_query_hdr->mld_qqi = 5; // 20 second query interval (QQIC)
            mld_query_hdr->mld_numsrc = 0;
            cp += sizeof(*mld_query_hdr);

            // iph->ip6_plen = htons(sizeof(mld_query_hdr) + sizeof(r_alert));
            iph->ip6_plen = htons(cp - (u_int8_t*)iph - sizeof(*iph));

            bcopy(&iph->ip6_src, &pseudo_hdr.src, sizeof(struct in6_addr));
            bcopy(&iph->ip6_dst, &pseudo_hdr.dst, sizeof(struct in6_addr));
            pseudo_hdr.uplen = htonl(sizeof(*mld_query_hdr));
            pseudo_hdr.zero[0] = 0;
            pseudo_hdr.zero[1] = 0;
            pseudo_hdr.zero[2] = 0;
            pseudo_hdr.nxthdr = IPPROTO_ICMPV6; // 78; // htonl(IPPROTO_ICMPV6);
            struct iovec iovecs[2];
            iovecs[0].iov_base = &pseudo_hdr;
            iovecs[0].iov_len = sizeof(pseudo_hdr);
            iovecs[1].iov_base = mld_query_hdr;
            iovecs[1].iov_len = sizeof(*mld_query_hdr);
            mld_query_hdr->mld_icmp6_hdr.icmp6_cksum =
                iov_csum(iovecs, 2);

            len = cp - (u_int8_t*)iph;
            return len;
        }
        break;
        default:
            fprintf(stderr, "amtgw: internal error, unknown family %d for "
                    "local query\n", family);
            return -1;
    }
    return -1;
}

