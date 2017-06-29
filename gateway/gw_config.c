#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include "gw.h"

typedef struct ConfigInput_s {
    char discovery_addr[MAX_ADDR_STRLEN];
    char query_addr[MAX_ADDR_STRLEN];
    char tunnel_addr[MAX_ADDR_STRLEN];
    char interface_name[IFNAMSIZ];
    char* last_fname;
    char** accept_routes;
    unsigned int accept_count;
    gw_t* instance;
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
            } else {
                fprintf(stderr, "%s %s failed to parse as ipv4\n",
                        name, in_str);
                return -1;
            }
#ifdef BSD
            addrp->sin_len = sizeof(struct sockaddr_in);
#endif
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addrp =
                (struct sockaddr_in6*)sock_addr;
            rc = inet_pton(AF_INET6, in_str, &addrp->sin6_addr);
            if (rc == 1) {
                addrp->sin6_family = AF_INET6;
            } else {
                fprintf(stderr, "%s %s failed to parse as ipv6\n",
                        name, in_str);
                return -1;
            }
#ifdef BSD
            addrp->sin_len = sizeof(struct sockaddr_in6);
#endif
            break;
        }
    }
    return 0;
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
handle_amt_port(ConfigInput* input, const char* value)
{
    return handle_uint16(&input->instance->amt_port, value,
            "AmtPort (-b/--amt-port)");
}

static int
handle_debug(ConfigInput* input, const char* value)
{
    input->instance->debug = TRUE;
    return 0;
}

static int
handle_data_family(ConfigInput* input, const char* value)
{
    return handle_family(&input->instance->data_family, value,
        "DataFamily (-n/--data-family)");
}

static int
handle_gateway_family(ConfigInput* input, const char* value)
{
    return handle_family(&input->instance->gateway_family, value,
        "TunnelFamily (-l/--tunnel-family)");
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
handle_discovery_addr(ConfigInput* input, const char* value)
{
    int rc = handle_string(input->discovery_addr,
            sizeof(input->discovery_addr), value,
            "DiscoveryAddr (-a/--discovery-addr)");
    return rc;
}

static int
handle_query_addr(ConfigInput* input, const char* value)
{
    int rc = handle_string(input->query_addr,
            sizeof(input->query_addr), value,
            "QueryAddr (-s/--query-addr)");
    return rc;
}

static int
handle_tunnel_addr(ConfigInput* input, const char* value)
{
    int rc = handle_string(input->tunnel_addr,
            sizeof(input->tunnel_addr), value,
            "TunnelAddr (-t/--tunnel-addr)");
    return rc;
}

static int
handle_route_accept(ConfigInput* input, const char* value)
{
    char** new_ptr = realloc(input->accept_routes,
            sizeof(char*)*(input->accept_count + 1));
    if (!new_ptr) {
        if (input->accept_routes) {
            free(input->accept_routes);
        }
        fprintf(stderr, "oom while allocating route_accept %s\n",
                value);
        exit(1);
    }
    char* val_cpy = strdup(value);
    if (!val_cpy) {
        free(new_ptr);
        fprintf(stderr, "oom while strduping route_accept %s\n",
                value);
        exit(1);
    }
    input->accept_routes = new_ptr;
    input->accept_routes[input->accept_count] = val_cpy;
    input->accept_count += 1;
    return 0;
}

static int
parse_route(char* in_str, prefix_t **output, int family, const char* name)
{
    int rc;
    char* slash_save = 0;
    struct in_addr in_addr;
    struct in6_addr in6_addr;
    void* addr = 0;
    char* ip_str = strtok_r(in_str, "/", &slash_save);
    *output = 0;
    if (!ip_str) {
        fprintf(stderr, "Internal error parsing %s as %s: "
                "first strtok_r null\n", in_str, name);
        return -1;
    }
    int limit = 32;
    switch (family) {
        case AF_INET:
            limit = 32;
            addr = &in_addr;
            break;
        case AF_INET6:
            limit = 128;
            addr = &in6_addr;
            break;
        default:
            fprintf(stderr, "unknown family %d is neither AF_INET(%d) nor "
                    "AF_INET6(%d)\n", family, AF_INET, AF_INET6);
            return -1;
    }
    rc = inet_pton(family, ip_str, addr);
    if (rc) {
        fprintf(stderr, "%s %s failed to parse as %s\n", name,
                ip_str, (family==AF_INET)?"ipv4":"ipv6");
        return -1;
    }
    char* pfx_str = strtok_r(NULL, "/", &slash_save);
    if (!pfx_str) {
        fprintf(stderr, "Missing prefix parsing %s as %s\n",
                in_str, name);
        return -1;
    }
    char* endptr = 0;
    long val = strtol(pfx_str, &endptr, 10);
    if (val < 0 || val > limit || endptr == pfx_str) {
        fprintf(stderr, "invalid prefix len %ld while parsing %s \"%s\": "
                "should be between 0 and %d\n", val, name, in_str, limit);
        return -1;
    }
    *output = prefix_build(family, addr, val);
    if (!*output) {
        fprintf(stderr, "failed to build prefix while parsing %s \"%s\"\n",
                name, in_str);
        return -1;
    }
    char* check = strtok_r(NULL, "/", &slash_save);
    if (check) {
        fprintf(stderr, "text ignored in %s after \"%s\": %s\n", name,
                in_str, check);
        return -1;
    }
    return 0;
}

static void
set_sockaddr_port(int family, void* sa, uint16_t net_port)
{
    switch(family) {
        case AF_INET:
        {
            struct sockaddr_in* sin = (struct sockaddr_in*)sa;
            sin->sin_port = net_port;
        }
        break;
        case AF_INET6:
        {
            struct sockaddr_in6* sin = (struct sockaddr_in6*)sa;
            sin->sin6_port = net_port;
        }
        break;
        default:
            assert(family == AF_INET || family == AF_INET6);
    }
}

static int
handle_config_finish(ConfigInput* input)
{
    gw_t* instance = input->instance;
    if (!instance->gateway_family) {
        if (instance->debug) {
            fprintf(stderr,
                    "%s: setting default inet for gateway family (-l)\n",
                    instance->name);
        }
        instance->gateway_family = AF_INET;
    }

    if (!instance->data_family) {
        if (instance->debug) {
            fprintf(stderr,
                    "%s: setting default inet for data family (-n)\n",
                    instance->name);
        }
        instance->data_family = AF_INET;
    }

    int rc = 0;

    rc |= parse_ip(input->discovery_addr, &instance->discovery_addr,
            instance->gateway_family,
            "DiscoveryAddr (-a/--discovery-addr)");
    set_sockaddr_port(instance->gateway_family, &instance->discovery_addr,
            htons(instance->amt_port));

    if (input->query_addr[0]) {
        instance->query_addr_set = 1;
        rc |= parse_ip(input->query_addr, &instance->local_addr,
                instance->data_family,
                "QueryAddr (-s/--query-addr)");
    }

    if (input->tunnel_addr[0]) {
        instance->tunnel_addr_set = 1;
        rc |= parse_ip(input->tunnel_addr, &instance->tunnel_addr,
                instance->gateway_family,
                "TunnelAddr (-t/--tunnel-addr)");
    }

    instance->accept_count = input->accept_count;
    instance->accept_strings = input->accept_routes;
    if (instance->accept_count) {
        instance->accept_routes = (route_filter_t*)malloc(
                sizeof(*instance->accept_routes) * instance->accept_count);
        if (!instance->accept_routes) {
            fprintf(stderr, "oom allocating %u routes\n",
                    instance->accept_count);
            exit(-1);
        }
        unsigned int i;
        for (i = 0; i < instance->accept_count; ++i) {
            char* rt_str = input->accept_routes[i];
            char* dash_save;
            char* src_str = strtok_r(rt_str, " -", &dash_save);
            if (!src_str) {
                fprintf(stderr, "Internal error: null from first strtok_r parsing AcceptRoute %s\n", rt_str);
                exit(-1);
            }
            prefix_t* src_pfx = 0;
            prefix_t* grp_pfx = 0;
            rc |= parse_route(src_str, &src_pfx, instance->data_family,
                    "RouteAccept (-r/--route-accept) src");
            char* grp_str = strtok_r(NULL, " -", &dash_save);
            if (grp_str) {
                rc |= parse_route(grp_str, &grp_pfx, instance->data_family,
                        "RouteAccept (-r/--route-accept) grp");
                char* check = strtok_r(NULL, " -", &dash_save);
                if (check) {
                    fprintf(stderr, "text ignored after RouteAccept(%s): "
                            "%s\n", rt_str, check);
                    rc |= -1;
                }
            }
            instance->accept_routes[i].source = src_pfx;
            instance->accept_routes[i].group = grp_pfx;
        }
    }

    if (instance->cap_iface_index == 0) {
        fprintf(stderr, "DataInterface (-c/--interface) wasn't set to a "
                "valid interface name\n");
        return -1;
    }

    if (rc) {
        return rc;
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
        { "DataFamily", handle_data_family },
        { "DataInterface", handle_data_interface },
        { "DebugLevel", handle_debug },
        { "DiscoveryAddr", handle_discovery_addr },
        { "QueryAddr", handle_query_addr },
        { "TunnelAddr", handle_tunnel_addr },
        { "RouteAccept", handle_route_accept },
        { "GatewayFamily", handle_gateway_family },
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
            "    -a/--discovery-addr <ip>: AMT relay discovery IP/anycast\n"
            "    -b/--amt-port <val>: Port to use for AMT data (default 2268)\n"
            "    -c/--interface <ifname>: Interface for sending native multicast data\n"
            "    -d/--debug: Turn on debugging messages\n"
            "    -l/--tunnel-family <inet|inet6>: ip family for AMT packets\n"
            "    -n/--data-family <inet|inet6>: ip family for multicast data\n"
            "    -r/--route-accept <src/pre>[-<grp/pre>]: (multiple ok) default\n"
            "           accepts everything, but if this is present, handle only joins\n"
            "           for source-group pairs listed.\n"
            "    -s/--query-addr <ip>: source IP addr for IGMP/MLD queries (must be\n"
            "           an address on -c <interface> or left out to pick a default\n"
            "    -t/--tunnel-addr <ip>: local IP addr to use for AMT (must be\n"
            "           an address on a local interface or left out to pick a default\n",
          name);
    exit(1);
}


int
gateway_parse_command_line(gw_t* instance, int argc, char** argv)
{
    int ch, rc = 0;
    ConfigInput input;
    bzero(&input, sizeof(input));
    input.instance = instance;

    struct option long_options[] = {
        { "discovery-addr", required_argument, 0, 'a' },
        { "amt-port", required_argument, 0, 'b' },
        { "interface", required_argument, 0, 'c' },
        { "debug", no_argument, 0, 'd' },
        { "tunnel-family", required_argument, 0, 'l' },
        { "data-family", required_argument, 0, 'n' },
        { "route-accept", required_argument, 0, 'r' },
        { "query-addr", required_argument, 0, 's' },
        { "tunnel-addr", required_argument, 0, 't' },
        { "file", required_argument, 0, 'f' },
        { "help", no_argument, 0, 'h' }
    };

    instance->amt_port = 2268;

    while ((ch = getopt_long(argc, argv, "a:b:c:dl:n:r:s:t:f:h",
                  long_options, NULL)) != EOF) {
        switch (ch) {
            case 'a': {
                rc = handle_discovery_addr(&input, optarg);
                break;
            }
            case 'b': {
                rc = handle_amt_port(&input, optarg);
                break;
            }
            case 'c': {
                rc = handle_data_interface(&input, optarg);
                break;
            }
            case 'd': {
                rc = handle_debug(&input, optarg);
                break;
            }
            case 'l': {
                rc = handle_gateway_family(&input, optarg);
                break;
            }
            case 'n': {
                rc = handle_data_family(&input, optarg);
                break;
            }
            case 'r': {
                rc = handle_route_accept(&input, optarg);
                break;
            }
            case 's': {
                rc = handle_query_addr(&input, optarg);
                break;
            }
            case 't': {
                rc = handle_tunnel_addr(&input, optarg);
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
        } else {
            fprintf(stderr, "Error finalizing config from command line.\n");
        }
        exit(1);
    }
    return 0;
}

