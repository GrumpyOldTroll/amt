#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include "relay.h"

typedef struct ConfigInput_s {
    char tunnel_addr[MAX_ADDR_STRLEN];
    char listen_addr[MAX_ADDR_STRLEN];
    char relay_addr[MAX_ADDR_STRLEN];
    char interface_name[IFNAMSIZ];
    char* last_fname;
    relay_instance* instance;
} ConfigInput;

static int
handle_string(char* buf, u_int buflen, const char* value,
        const char* strname)
{
    if (!value) {
        fprintf(stderr, "error: %s requires a value.\n", strname);
        return -1;
    }
    u_int len = strlen(value);
    if (len >= buflen) {
        fprintf(stderr,
            "error: %s \"%s\" with length %u exceeds "
            "bufsize %u\n", strname, value, len, buflen);
        return -1;
    }
    memcpy(buf, value, len);
    buf[len] = 0;
    return 0;
}

static int
handle_tunnel_addr(ConfigInput* input, const char* value)
{
    int rc = handle_string(input->tunnel_addr, sizeof(input->tunnel_addr),
            value, "TunnelAddr (-s/--tunnel-addr)");
    return rc;
}

static int
handle_relay_addr(ConfigInput* input, const char* value)
{
    int rc = handle_string(input->relay_addr, sizeof(input->relay_addr),
            value, "RelayAddr (-r/--relay-addr)");
    return rc;
}

static int
handle_listen_addr(ConfigInput* input, const char* value)
{
    int rc = handle_string(input->listen_addr, sizeof(input->listen_addr),
            value, "DiscoveryAddr (-a/--anycast)");
    return rc;
}

static int
handle_data_interface(ConfigInput* input, const char* value)
{
    int rc = handle_string(input->instance->cap_iface_name,
            sizeof(input->instance->cap_iface_name), value,
            "DataInterface (-c/--interface)");
    if (!rc) {
        input->instance->cap_iface_index = if_nametoindex(value);
        if (input->instance->cap_iface_index == 0) {
            char temp[256];
            snprintf(temp, sizeof(temp), "failed if_nametoindex(%s)",
                     value);
            perror(temp);
            rc = -1;
        }
    }
    return rc;
}


static int
handle_family(int* fam, const char* value, const char* name)
{
    if (!value) {
        fprintf(stderr, "error: %s requires a value (inet or inet6).\n",
                name);
        return -1;
    }
    if (strcmp(value, "inet") == 0) {
        *fam = AF_INET;
    } else if (strcmp(value, "inet6") == 0) {
        *fam = AF_INET6;
    } else {
        fprintf(stderr, "Unknown %s: %s (should be inet or inet6)\n",
                name, value);
        return -1;
    }
    return 0;
}

static int
handle_tunnel_family(ConfigInput* input, const char* value)
{
    return handle_family(&input->instance->tunnel_af, value,
            "TunnelFamily (-l/--tun-relay)");
}

static int
handle_relay_family(ConfigInput* input, const char* value)
{
    return handle_family(&input->instance->relay_af, value,
            " RelayFamily (-n/--net-relay)");
}



static int
handle_uint16(uint16_t* val, const char* value, const char* name)
{
    if (!value) {
        fprintf(stderr, "error: %s requires a value below 65536.\n", name);
        return -1;
    }
    char* endptr = 0;
    long port_val = strtol(value, &endptr, 10);
    if (port_val > 0xffff || port_val < 0 || endptr == value ||
            endptr == 0) {
        fprintf(stderr, "invalid %s: %s (should be an int below 65536)\n", name, value);
        return -1;
    }
    *val = (uint16_t)port_val;
    return 0;
}

static int
handle_bit(int* flags, int flag_val, const char* value, const char* name)
{
    if (!value) {
        BIT_SET(*flags, flag_val);
        return 0;
    }
    uint16_t val = 0;
    int rc = handle_uint16(&val, value, name);
    if (val) {
        BIT_SET(*flags, flag_val);
    }
    return rc;
}

static int
handle_nat_mode(ConfigInput* input, const char* value)
{
    return handle_bit(&input->instance->relay_flags, RELAY_FLAG_NAT_MODE,
            value, "NatMode (-m/--nat-mode)");
}

static int
handle_debug(ConfigInput* input, const char* value)
{
    return handle_bit(&input->instance->relay_flags, RELAY_FLAG_DEBUG,
            value, "DebugLevel (-d/--debug)");
}

static int
handle_external(ConfigInput* input, const char* value)
{
    return handle_bit(&input->instance->relay_flags, RELAY_FLAG_EXTERNAL,
            value, "Externaldata (-e/--external)");
}

static int
handle_icmp_suppress(ConfigInput* input, const char* value)
{
    return handle_bit(&input->instance->relay_flags, RELAY_FLAG_NOICMP,
            value, "SuppressICMP (-i/--icmp-suppress)");
}

static int
handle_nonraw_port(ConfigInput* input, const char* value)
{
    relay_instance* instance = input->instance;
    if (!strcmp(value, "all")) {
        BIT_RESET(instance->relay_flags, RELAY_FLAG_NONRAW);
        return 0;
    }
    uint16_t port_val = 0;
    int rc = handle_uint16(&port_val, value, "DataPort (-w/--non-raw)");
    if (rc) {
        return rc;
    }
    u_int16_t* new_ptr = realloc(instance->nonraw_ports,
            sizeof(u_int16_t)*(instance->nonraw_count +1));
    if (!new_ptr) {
        if (instance->nonraw_ports) {
            free(instance->nonraw_ports);
        }
        fprintf(stderr, "oom while allocating nonraw port %u\n",
                (unsigned int)instance->nonraw_count);
        exit(1);
    }
    BIT_SET(instance->relay_flags, RELAY_FLAG_NONRAW);
    instance->nonraw_ports = new_ptr;
    instance->nonraw_ports[instance->nonraw_count] =
        (u_int16_t)port_val;
    instance->nonraw_count += 1;
    return 0;
}

static int
handle_dequeue_length(ConfigInput* input, const char* value)
{
    uint16_t val = 0;
    int rc = handle_uint16(&val, value,
            "DequeueLen (-q/--queue-length)");
    if (rc) {
        return rc;
    }

    input->instance->dequeue_count = val;
    return 0;
}

static int
handle_amt_port(ConfigInput* input, const char* value)
{
    return handle_uint16(&input->instance->amt_port, value,
            "AmtPort (-b/--amt-port)");
}

static int
handle_url_port(ConfigInput* input, const char* value)
{
    fprintf(stderr, "handle_url_port: \"%s\"\n", value);
    if (!strcmp(value, "none")) {
        input->instance->relay_url_port = 0;
        return 0;
    }
    return handle_uint16(&input->instance->relay_url_port, value,
            "RelayUrlPort (-p/--port)");
}

static int
parse_ip(char* in_str, struct sockaddr_storage* sock_addr,
        int family, const char* name)
{
    int rc;
    switch (family) {
        case AF_INET: {
            struct sockaddr_in *addrp =
                (struct sockaddr_in*)sock_addr;
            rc = inet_pton(AF_INET, in_str, &addrp->sin_addr);
            if (rc == 1) {
                addrp->sin_family = AF_INET;
#ifdef BSD
                addrp->sin_len = sizeof(*addrp);
#endif
            } else {
                fprintf(stderr, "%s %s failed to parse as ipv4\n",
                        name, in_str);
                return -1;
            }
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addrp =
                (struct sockaddr_in6*)sock_addr;
            rc = inet_pton(AF_INET6, in_str, &addrp->sin6_addr);
            if (rc == 1) {
                addrp->sin6_family = AF_INET6;
#ifdef BSD
                addrp->sin_len = sizeof(*addrp);
#endif
            } else {
                fprintf(stderr, "%s %s failed to parse as ipv6\n",
                        name, in_str);
                return -1;
            }
            break;
        }
    }

    {
        char str[MAX_SOCK_STRLEN];
        fprintf(stderr, "config %s: parsed %s from %s\n", name,
                sock_ntop(family, sock_addr, str, sizeof(str)), in_str);
    }
    return 0;
}

static int
handle_config_finish(ConfigInput* input)
{
    relay_instance* instance = input->instance;

    // permit legacy argument--including prefixlen on addr--for listen_addr
    // even though the prefix len is unused:
    // "192.52.193.1/32" or "192.52.193.1", either is fine (/32 ignored)
    char* pstr = NULL;
    char* tok = &input->listen_addr[0];
    pstr = strsep(&tok, "/");
    if (!input->listen_addr[0]) {
        if (instance->relay_af == AF_INET) {
            strcpy(input->listen_addr, "192.53.193.1");
        } else if (instance->relay_af == AF_INET6) {
            strcpy(input->listen_addr, "2001:3::1");
        }
    }
    if (!input->relay_addr[0]) {
        if (instance->relay_af == AF_INET) {
            strcpy(input->relay_addr, input->listen_addr);
        } else if (instance->relay_af == AF_INET6) {
            strcpy(input->relay_addr, input->listen_addr);
        }
    }
    if (!input->tunnel_addr[0]) {
        if (instance->tunnel_af == AF_INET) {
            strcpy(input->tunnel_addr, "0.0.0.0");
        } else if (instance->tunnel_af == AF_INET6) {
            strcpy(input->tunnel_addr, "::");
        }
    }
    int rc = parse_ip(pstr, &instance->listen_addr, instance->relay_af,
            "DiscoveryAddr (-a/--anycast)");
    rc |= parse_ip(input->tunnel_addr, &instance->tunnel_addr,
            instance->tunnel_af, "TunnelAddr (-s,--tunnel-addr)");
    rc |= parse_ip(input->relay_addr, &instance->relay_addr,
            instance->relay_af, "RelayAddr (-r/--relay-addr)");

    if (instance->cap_iface_index == 0) {
        fprintf(stderr, "DataInterface (-c/--interface) wasn't set to a valid interface name\n");
        return -1;
    }

    if (rc) {
        return rc;
    }

    if (instance->relay_af == AF_INET) {
        struct sockaddr_in* paddr =
            (struct sockaddr_in*)&instance->listen_addr;
        paddr->sin_port = htons(instance->amt_port);
    } else {
        struct sockaddr_in6* paddr =
            (struct sockaddr_in6*)&instance->listen_addr;
        paddr->sin6_port = htons(instance->amt_port);
    }
    {
        char str[MAX_ADDR_STRLEN];
        fprintf(stderr, "listen_addr: %s from %s\n",
                sock_ntop(instance->relay_af, &instance->listen_addr,
                    str, sizeof(str)), pstr);
    }


    // TBD: allow non-raw sockets with ipv6 data (by adding fix in
    // data_socket_read and data_socket_init, where it says TBD)
    // --jake 2017-06-14
    if (instance->tunnel_af == AF_INET6 && instance->nonraw_count) {
        fprintf(stderr, "ipv6 data with nonraw socket is not currently supported\n");
        return -1;
    }

    return 0;
}

static int
config_param(ConfigInput* input,
        const char* param, const char* value)
{
    struct {
        const char* name;
        int (*fn)(ConfigInput*,const char*);
    } line_handlers[] = {
        { "AmtPort", handle_amt_port },
        { "DataInterface", handle_data_interface },
        { "DataPort", handle_nonraw_port },
        { "DebugLevel", handle_debug },
        { "DequeueLen", handle_dequeue_length },
        { "DiscoveryAddr", handle_listen_addr },
        { "NatMode", handle_nat_mode },
        { "RelayAddr", handle_relay_addr },
        { "ExternalData", handle_external },
        { "RelayFamily", handle_relay_family },
        { "RelayUrlPort", handle_url_port },
        { "SuppressICMP", handle_icmp_suppress },
        { "TunnelAddr", handle_tunnel_addr },
        { "TunnelFamily", handle_tunnel_family },
    };
    int nhandlers = sizeof(line_handlers)/sizeof(line_handlers[0]);
    int i;
    for (i = 0; i < nhandlers; i++) {
        if (!strcmp(line_handlers[i].name, param)) {
            return line_handlers[i].fn(input, value);
        }
    }
    fprintf(stderr, "Did not understand config %s. Use one of:\n", param);
    for (i = 0; i < nhandlers; i++) {
        fprintf(stderr, "    %s\n", line_handlers[i].name);
    }
    return -1;
}

static int
config_read(ConfigInput* input, const char* fname)
{
    int rc = 0;

    char buf[16384];
    char* data = 0;
    u_int line = 1;
    if (input->last_fname) {
        free(input->last_fname);
    }
    input->last_fname = strdup(fname);

    FILE* fp = fopen(fname, "r");
    if (!fp) {
        fprintf(stderr, "Error opening config file \"%s\": %s\n", fname, strerror(errno));
        exit(1);
    }

    while (0 != (data = fgets(buf, sizeof(buf), fp))) {
        char* comment_begin = strchr(data, '#');
        if (comment_begin) {
            *comment_begin = 0;
        }
        char* separator_save;
        char* arg = 0;
        char* op;
        op = strtok_r(data, " \t\r\n", &separator_save);
        if (op) {
            arg = strtok_r(NULL, " \t\r\n", &separator_save);
            rc |= config_param(input, op, arg);
            if (rc) {
                fprintf(stderr, "config error: file \"%s\" line %u op %s\n",
                        fname, line, op);
                exit(1);
            }
        }

        ++line;
    }

    if (ferror(fp)) {
        fprintf(stderr, "Error reading config file \"%s\", line %u: %s\n",
                fname, line, strerror(errno));
        exit(1);
    }

    fclose(fp);

    return rc;
}


static void
usage(char* name)
{
    fprintf(stderr, "usage: %s -a <ip> -c <interface> [options]\n"
            "  Options:\n"
            "    -a/--discovery-addr <ip>: IP (matching -l) to listen for AMT discovery packets on\n"
            "    -r/--relay-addr <ip>: IP (matching -l) to use for discovery response and for tunnel\n"
            "    -s/--tunnel-addr <ip>: IP (matching -n) to use for source of queries inside the tunnel\n"
            "    -c/--interface <ifname>: Interface to receive native multicast data\n"
            "    -d/--debug: Turn on debugging messages\n"
            "    -q/--queue-length <val>: Packets to handle at once (default 10)\n"
            "    -b/--amt-port <val>: Port to use for AMT data (default 2268)\n"
            "    -p/--port <val|\"none\">: port to listen for stats requests\n"
            "    -n/--net-family <inet|inet6>: ip family for multicast data\n"
            "    -l/--tun-family <inet|inet6>: ip family for AMT packets (discovery and \n"
            "    -w/--non-raw <val>: (multiple ok) Accept data on this port. (By,\n"
            "              defaultraw captures all. Adding this and \n"
            "              icmp-suppress permits non-root, and captures only\n"
            "              specified ports)\n"
            "    -e/--external: data is arriving from an external interface\n"
            "              (doesn't recompute checksums, since nic did it\n",
          name);
    exit(1);
}

int
relay_parse_command_line(relay_instance* instance, int argc, char** argv)
{
    int ch, rc = 0;
    ConfigInput input;
    bzero(&input, sizeof(input));
    input.instance = instance;

    struct option long_options[] = {
        { "anycast", required_argument, 0, 'a' },
        { "discovery-addr", required_argument, 0, 'a' },
        { "amt-port", required_argument, 0, 'b' },
        { "debug", no_argument, 0, 'd' },
        { "nat-mode", no_argument, 0, 'm' },
        { "icmp-suppress", no_argument, 0, 'i' },
        { "queue-length", required_argument, 0, 'q' },
        { "queue-thresh", required_argument, 0, 't' },
        { "help", no_argument, 0, 'h' },
        { "interface", required_argument, 0, 'c' },
        { "port", required_argument, 0, 'p' },
        { "file", required_argument, 0, 'f' },
        { "net-relay", required_argument, 0, 'n' },
        { "tun-relay", required_argument, 0, 'l' },
        { "non-raw", required_argument, 0, 'w' },
        { "external", required_argument, 0, 'e' },
        { "relay-addr", required_argument, 0, 'r' },
        { "tunnel-addr", required_argument, 0, 's' }
    };

    // TBD: config file instead of command line args.
    while ((ch = getopt_long(argc, argv, "u:a:dp:q:t:g:b:mn:c:l:r:s:eiw:f:h",
                  long_options, NULL)) != EOF) {
        switch (ch) {
            case 's': {
                rc = handle_tunnel_addr(&input, optarg);
                break;
            }
            case 'r': {
                rc = handle_relay_addr(&input, optarg);
                break;
            }
            case 'l': {
                rc = handle_tunnel_family(&input, optarg);
                break;
            }
            case 'n':
                rc = handle_relay_family(&input, optarg);
                break;
            case 'c': {
                rc = handle_data_interface(&input, optarg);
                break;
            }
            case 'a': {
                rc = handle_listen_addr(&input, optarg);
                break;
            }
            case 'm': {
                rc = handle_nat_mode(&input, optarg);
                break;
            }
            case 'd': {
                rc = handle_debug(&input, optarg);
                break;
            }
            case 'e':
                rc = handle_external(&input, optarg);
                break;
            case 'i':
                rc = handle_icmp_suppress(&input, optarg);
                break;
            case 'w': {
                rc = handle_nonraw_port(&input, optarg);
                break;
            }
            case 'q': {
                rc = handle_dequeue_length(&input, optarg);
                break;
            }
            case 'b': {
                rc = handle_amt_port(&input, optarg);
                break;
            }
            case 'p': {
                rc = handle_url_port(&input, optarg);
                break;
            }
            case 'f':
                if (optarg == NULL) {
                    fprintf(stderr, "must specify config file with -f\n");
                    exit(1);
                }
                if (config_read(&input, optarg) != 0) {
                    fprintf(stderr, "failure parsing config file %s",
                          optarg);
                    exit(1);
                }
                break;
            case 't':
                if (optarg == NULL) {
                    // fprintf( stderr, "must specify the queueing threshold (-t 100 default, in ms)\n");
                }
                // instance->qdelay_thresh = strtol(optarg, NULL, 10);
            case 'u':
            case 'g':
                fprintf(stderr, "deprecated option '%c' ignored\n", ch);
                break;
            default:
                fprintf(stderr, "unknown argument '%c'\n", ch);
            case 'h':
                usage(argv[0]);
        }
        if (rc) {
            fprintf(stderr, "error parsing command line args at %c (%s)\n",
                    ch, optarg?optarg:"(no arg)");
            exit(1);
        }
    }

    rc |= handle_config_finish(&input);
    if (rc) {
        if (input.last_fname) {
            fprintf(stderr, "Error finalizing from config file %s.\n",
                    input.last_fname);
            free(input.last_fname);
        } else {
            fprintf(stderr, "Error finalizing config from command line.\n");
        }
        exit(1);
    }
    if (input.last_fname) {
        free(input.last_fname);
    }
    return 0;
}

