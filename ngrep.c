/*
 * Copyright (c) 2017  Jordan Ritter <jpr5@darkridge.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 */

#if defined(BSD) || defined(SOLARIS) || defined(MACOSX)
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/tty.h>
#include <pwd.h>
#endif

#if defined(OSF1)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/route.h>
#include <sys/mbuf.h>
#include <arpa/inet.h>
#include <unistd>
#include <pwd.h>
#endif

#if defined(LINUX) || defined(__GLIBC__) || defined(__GNU__)
#include <getopt.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#endif

#if defined(AIX)
#include <sys/machine.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <unistd.h>
#include <pwd.h>
#endif

#if defined(_WIN32)
#include <io.h>
#include <getopt.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <types.h>
#include <config.h>

#define strcasecmp stricmp
#define strncasecmp strnicmp

#else

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#endif

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <locale.h>

#if !defined(_WIN32)
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <dirent.h>
#include <time.h>
#endif

#include <pcap.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if USE_IPv6 && !defined(_WIN32)
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#if USE_PCRE
#include <pcre.h>
#else
#include <regex.h>
#endif

#include "ngrep.h"

#if !defined(_WIN32)
/*
 * Container Resolution Data Structures
 */

#define MAX_CONTAINERS 1024
#define MAX_CONTAINER_NAME 64
#define MAX_IP_ADDR_LEN 64
#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct container_entry {
    char ip_addr[MAX_IP_ADDR_LEN];
    char container_name[MAX_CONTAINER_NAME];
    time_t last_seen;
    uint32_t netns_id;
};

struct container_cache {
    struct container_entry entries[MAX_CONTAINERS];
    uint32_t count;
    time_t last_refresh;
};

struct netns_info {
    uint32_t netns_id;
    int pid;
    char container_id[65];
    char container_name[MAX_CONTAINER_NAME];
};

/* Global container cache */
static struct container_cache g_container_cache = {0};

#endif /* !defined(_WIN32) */

/* Container resolution function prototypes - always declared but conditionally implemented */
static int refresh_container_cache(void);
static const char* lookup_container_name(const char* ip_addr);
static int discover_containers_via_netns(void);
static int parse_container_from_proc(int pid, struct netns_info *info);
static int get_netns_for_ip(const char* ip_addr, uint32_t* netns_id);
static void cleanup_expired_cache_entries(void);
static int discover_container_ips_via_netlink(void);
static int parse_netlink_response(char* buf, int len);
static int send_netlink_request(int sock, int type, int family);
static void format_ip_with_container(const char* ip_addr, char* output, size_t output_size);

/*
 * Configuration Options
 */

uint32_t snaplen = 65535, limitlen = 65535, promisc = 1, to = 100;
uint32_t match_after = 0, keep_matching = 0, matches = 0, max_matches = 0;
uint32_t seen_frames = 0;

#if USE_TCPKILL
uint32_t tcpkill_active = 0;
#endif

uint8_t  re_match_word = 0, re_ignore_case = 0, re_multiline_match = 1;
uint8_t  show_empty = 0, show_hex = 0, show_proto = 0, quiet = 0;
uint8_t  invert_match = 0, bin_match = 0;
uint8_t  live_read = 1, want_delay = 0;
uint8_t  dont_dropprivs = 0;
uint8_t  enable_hilite = 0;

/*
 * Container Resolution Configuration
 */
uint8_t  resolve_containers = 0;
uint32_t container_cache_ttl = 30;
uint32_t container_resolve_timeout = 1;

char *read_file = NULL, *dump_file = NULL;
char *usedev = NULL;

char nonprint_char = '.';

/*
 * GNU Regex/PCRE
 */

#if USE_PCRE
int32_t err_offset;
char *re_err = NULL;

pcre *pattern = NULL;
pcre_extra *pattern_extra = NULL;
#else
const char *re_err = NULL;

struct re_pattern_buffer pattern;
#endif

/*
 * Matching
 */

char *match_data = NULL, *bin_data = NULL;
uint16_t match_len = 0;
int8_t (*match_func)(unsigned char *, uint32_t, uint16_t *, uint16_t *) = &blank_match_func;

int8_t dump_single = 0;
void (*dump_func)(unsigned char *, uint32_t, uint16_t, uint16_t) = &dump_formatted;

/*
 * BPF/Network
 */

char *filter = NULL, *filter_file = NULL;
char pc_err[PCAP_ERRBUF_SIZE];
uint8_t link_offset;
uint8_t radiotap_present = 0;
uint8_t include_vlan = USE_VLAN_HACK;

pcap_t *pd = NULL, *pd_dumppcap = NULL;
pcap_dumper_t *pd_dump = NULL;
struct bpf_program pcapfilter;
struct in_addr net, mask;

/*
 * Timestamp/delay functionality
 */

struct timeval prev_ts = {0, 0}, prev_delay_ts = {0,0};
#if defined(_WIN32)
struct timeval delay_tv;
FD_SET delay_fds;
SOCKET delay_socket = 0;
#endif

void (*print_time)(struct pcap_pkthdr *) = NULL, (*dump_delay)(struct pcap_pkthdr *) = dump_delay_proc_init;


/*
 * Window-size functionality (adjust output based on width of console display)
 */

uint32_t ws_row, ws_col = 80, ws_col_forced = 0;


int main(int argc, char **argv) {
    int32_t c;

    signal(SIGINT,   clean_exit);
    signal(SIGABRT,  clean_exit);

#if !defined(_WIN32)
    signal(SIGQUIT,  clean_exit);
    signal(SIGPIPE,  clean_exit);
    signal(SIGWINCH, update_windowsize);
#endif

    setlocale(LC_ALL, "");

#if !defined(_WIN32)
    {
        char const *locale = getenv("LANG");
        if (locale == NULL)
            locale = "en_US";

        setlocale(LC_CTYPE, locale);
    }
#endif

    while ((c = getopt(argc, argv, "LNhXViwqpevxlDtTRMK:Cs:n:c:d:A:I:O:S:P:F:W:E::")) != EOF) {
        switch (c) {
            case 'W': {
                if (!strcasecmp(optarg, "normal"))
                    dump_func = &dump_formatted;
                else if (!strcasecmp(optarg, "byline"))
                    dump_func = &dump_byline;
                else if (!strcasecmp(optarg, "none"))
                    dump_func = &dump_unwrapped;
                else if (!strcasecmp(optarg, "single")) {
                    dump_func = &dump_unwrapped;
                    dump_single = 1;
                } else {
                    printf("fatal: unknown wrap method '%s'\n", optarg);
                    usage();
                }
            } break;

            case 'F':
                filter_file = optarg;
                break;
            case 'P':
                nonprint_char = *optarg;
                break;
            case 'S': {
                limitlen = _atoui32(optarg);
                break;
            }
            case 'O':
                dump_file = optarg;
                break;
            case 'I':
                read_file = optarg;
                break;
            case 'A':
                match_after = _atoui32(optarg);
                if (match_after < UINT32_MAX)
                    match_after++;
                break;
#if defined(_WIN32)
            case 'L':
                win32_listdevices();
                clean_exit(2);
            case 'd':
                usedev = win32_usedevice(optarg);
                break;
#else
            case 'L':
                perror("-L is a Win32-only option");
                clean_exit(2);
            case 'd':
                usedev = optarg;
                /* Linux: any = DLT_LINUX_SLL, pcap says incompatible with VLAN */
                if (!strncasecmp(usedev, "any", 3))
                    include_vlan = 0;
                break;
#endif
            case 'c':
                ws_col_forced = atoi(optarg);
                break;
            case 'n':
                max_matches = _atoui32(optarg);
                break;
            case 's': {
                uint16_t value = _atoui32(optarg);
                if (value > 0)
                    snaplen = value;
            } break;
            case 'C':
                enable_hilite = 1;
                break;
            case 'M':
                re_multiline_match = 0;
                break;
            case 'R':
                dont_dropprivs = 1;
                break;
            case 'T':
                if (print_time == &print_time_diff) {
                    print_time = print_time_offset;
                    memset(&prev_ts, 0, sizeof(prev_ts));
                } else {
                    print_time = &print_time_diff;
#if defined(_WIN32)
                    prev_ts.tv_sec  = (uint32_t)time(NULL);
                    prev_ts.tv_usec = 0;
#else
                    gettimeofday(&prev_ts, NULL);
#endif
                }
                break;
            case 't':
                print_time = &print_time_absolute;
                break;
            case 'D':
                want_delay = 1;
                break;
            case 'l':
                setvbuf(stdout, NULL, _IOLBF, 0);
                break;
            case 'x':
                show_hex++;
                break;
            case 'v':
                invert_match++;
                break;
            case 'e':
                show_empty++;
                break;
            case 'p':
                promisc = 0;
                break;
            case 'q':
                quiet++;
                break;
            case 'w':
                re_match_word++;
                break;
            case 'i':
                re_ignore_case++;
                break;
            case 'V':
                version();
            case 'X':
                bin_match++;
                break;
            case 'N':
                show_proto++;
                break;
#if USE_TCPKILL
            case 'K':
                tcpkill_active = _atoui32(optarg);
                break;
#endif
            case 'E': {
                resolve_containers = 1;
                if (optarg) {
                    /* Parse optional container options: ttl=30,timeout=1 */
                    char *token = strtok(optarg, ",");
                    while (token) {
                        if (strncmp(token, "ttl=", 4) == 0) {
                            container_cache_ttl = _atoui32(token + 4);
                        } else if (strncmp(token, "timeout=", 8) == 0) {
                            container_resolve_timeout = _atoui32(token + 8);
                        }
                        token = strtok(NULL, ",");
                    }
                }
                break;
            }
            case 'h':
                usage();
            default:
                usage();
        }
    }

    if (show_hex && dump_func != &dump_formatted) {
        printf("fatal: -x (hex dump) is incompatible with -W (alternate format)\n");
        usage();
    }

    if (argv[optind])
        match_data = argv[optind++];

#if USE_TCPKILL
    if (tcpkill_active)
        tcpkill_init();
#endif

    /* Setup PCAP input */

    if (setup_pcap_source())
        clean_exit(2);

    /* Setup BPF filter */

    if (setup_bpf_filter(argv)) {
        include_vlan = 0;
        if (filter) { free(filter); filter = NULL; }

        if (setup_bpf_filter(argv)) {
            pcap_perror(pd, "pcap");
            clean_exit(2);
        }
    }

    if (filter) {
        if (quiet < 2)
            printf("filter: %s\n", filter);
        free(filter);
    }

    /* Setup matcher */

    if (match_data) {
        if (setup_matcher())
            clean_exit(2);

        if (quiet < 2 && strlen(match_data))
            printf("%smatch: %s%s\n", invert_match?"don't ":"",
                   (bin_data && !strchr(match_data, 'x'))?"0x":"", match_data);

        if (re_match_word) free(match_data);
    }

    /* Misc */

    if (dump_file) {
        pd_dump = pcap_dump_open(pd, dump_file);
        if (!pd_dump) {
            fprintf(stderr, "fatal: %s\n", pcap_geterr(pd));
            clean_exit(2);
        } else printf("output: %s\n", dump_file);
    }

    update_windowsize(0);

#if defined(_WIN32)
    win32_initwinsock();
#endif

#if !defined(_WIN32)
    /* Initialize container cache if container resolution is enabled */
    /* Note: This must be done BEFORE dropping privileges to access Docker socket */
    if (resolve_containers) {
        int cache_result = refresh_container_cache();
        if (cache_result != 0) {
            fprintf(stderr, "warning: failed to initialize container cache (returned %d)\n", cache_result);
        } else {
            fprintf(stderr, "info: container cache initialized with %u entries\n", g_container_cache.count);
        }
    }
#endif

#if !defined(_WIN32) && USE_DROPPRIVS
    drop_privs();
#endif

    while (pcap_loop(pd, -1, (pcap_handler)process, 0));

    clean_exit(0);

    /* NOT REACHED */
    return 0;
}

int setup_pcap_source(void) {
    if (read_file) {

        if (!(pd = pcap_open_offline(read_file, pc_err))) {
            perror(pc_err);
            return 1;
        }

        live_read = 0;
        printf("input: %s\n", read_file);

    } else {

        char *dev = usedev ? usedev :
#if defined(_WIN32)
            win32_choosedevice();
#else
            pcap_lookupdev(pc_err);
#endif

        if (!dev) {
            perror(pc_err);
            return 1;
        }

        if ((pd = pcap_open_live(dev, snaplen, promisc, to, pc_err)) == NULL) {
            perror(pc_err);
            return 1;
        }

        if (pcap_lookupnet(dev, &net.s_addr, &mask.s_addr, pc_err) == -1) {
            perror(pc_err);
            memset(&net, 0, sizeof(net));
            memset(&mask, 0, sizeof(mask));
        }

        if (quiet < 2) {
            printf("interface: %s", dev);
            if (net.s_addr && mask.s_addr) {
                printf(" (%s/", inet_ntoa(net));
                printf("%s)", inet_ntoa(mask));
            }
            printf("\n");
        }
    }

    switch(pcap_datalink(pd)) {
        case DLT_EN10MB:
            link_offset = ETHHDR_SIZE;
            break;

        case DLT_IEEE802:
            link_offset = TOKENRING_SIZE;
            break;

        case DLT_FDDI:
            link_offset = FDDIHDR_SIZE;
            break;

        case DLT_SLIP:
            link_offset = SLIPHDR_SIZE;
            break;

        case DLT_PPP:
            link_offset = PPPHDR_SIZE;
            break;

#if HAVE_DLT_LOOP
        case DLT_LOOP:
#endif
        case DLT_NULL:
            link_offset = LOOPHDR_SIZE;
            break;

#if HAVE_DLT_RAW
        case DLT_RAW:
            link_offset = RAWHDR_SIZE;
            break;
#endif

#if HAVE_DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            link_offset = ISDNHDR_SIZE;
            include_vlan = 0;
            break;
#endif

#if HAVE_DLT_IEEE802_11_RADIO
        case DLT_IEEE802_11_RADIO:
            radiotap_present = 1;
#endif

#if HAVE_DLT_IEEE802_11
        case DLT_IEEE802_11:
            link_offset = IEEE80211HDR_SIZE;
            break;
#endif

#if HAVE_DLT_PFLOG
        case DLT_PFLOG:
            link_offset = PFLOGHDR_SIZE;
            break;
#endif

#if HAVE_DLT_IPNET
        case DLT_IPNET:
            link_offset = IPNETHDR_SIZE;
            include_vlan = 0;
            break;
#endif

        default:
            fprintf(stderr, "fatal: unsupported interface type %u\n", pcap_datalink(pd));
            return 1;
    }

    return 0;
}

int setup_bpf_filter(char **argv) {
    if (filter_file) {
        char buf[1024] = {0};
        FILE *f = fopen(filter_file, "r");

        if (!f || !fgets(buf, sizeof(buf)-1, f)) {
            fprintf(stderr, "fatal: unable to get filter from %s: %s\n", filter_file, strerror(errno));
            usage();
        }

        fclose(f);

        filter = get_filter_from_string(buf);

        if (pcap_compile(pd, &pcapfilter, filter, 0, mask.s_addr))
            return 1;

    } else if (argv[optind]) {
        filter = get_filter_from_argv(&argv[optind]);

        if (pcap_compile(pd, &pcapfilter, filter, 0, mask.s_addr)) {
            free(filter);
            filter = get_filter_from_argv(&argv[optind-1]);

#if USE_PCAP_RESTART
            PCAP_RESTART_FUNC();
#endif

            if (pcap_compile(pd, &pcapfilter, filter, 0, mask.s_addr))
                return 1;

            match_data = NULL;
        }

    } else {
        filter = include_vlan ? strdup(BPF_TEMPLATE_IP_VLAN) : strdup(BPF_TEMPLATE_IP);

        if (pcap_compile(pd, &pcapfilter, filter, 0, mask.s_addr))
            return 1;
    }

    if (pcap_setfilter(pd, &pcapfilter))
        return 1;

    return 0;
}

int setup_matcher(void) {
    if (bin_match) {
        uint32_t i = 0, n;
        uint32_t len;
        char *s, *d;

        if (re_match_word || re_ignore_case) {
            fprintf(stderr, "fatal: regex switches are incompatible with binary matching\n");
            return 1;
        }

        len = (uint32_t)strlen(match_data);
        if (len % 2 != 0 || !strishex(match_data)) {
            fprintf(stderr, "fatal: invalid hex string specified\n");
            return 1;
        }

        bin_data = (char*)malloc(len / 2);
        memset(bin_data, 0, len / 2);
        d = bin_data;

        if ((s = strchr(match_data, 'x')))
            len -= (uint32_t)(++s - match_data - 1);
        else s = match_data;

        while (i <= len) {
            sscanf(s+i, "%2x", &n);
            *d++ = n;
            i += 2;
        }

        match_len = len / 2;
        match_func = &bin_match_func;

    } else {

#if USE_PCRE
        uint32_t pcre_options = PCRE_UNGREEDY;

        if (re_ignore_case)
            pcre_options |= PCRE_CASELESS;

        if (re_multiline_match)
            pcre_options |= PCRE_DOTALL;
#else
        re_syntax_options = RE_CHAR_CLASSES | RE_NO_BK_PARENS | RE_NO_BK_VBAR |
            RE_CONTEXT_INDEP_ANCHORS | RE_CONTEXT_INDEP_OPS;

        if (re_multiline_match)
            re_syntax_options |= RE_DOT_NEWLINE;

        if (re_ignore_case) {
            uint32_t i;
            char *s;

            pattern.translate = (char*)malloc(256);
            s = pattern.translate;

            for (i = 0; i < 256; i++)
                s[i] = i;
            for (i = 'A'; i <= 'Z'; i++)
                s[i] = i + 32;

            s = match_data;
            while (*s) {
                *s = tolower(*s);
                s++;
            }

        } else pattern.translate = NULL;
#endif

        if (re_match_word) {
            char *word_regex = (char*)malloc(strlen(match_data) * 3 + strlen(WORD_REGEX));
            sprintf(word_regex, WORD_REGEX, match_data, match_data, match_data);
            match_data = word_regex;
        }

#if USE_PCRE
        pattern = pcre_compile(match_data, pcre_options, (const char **)&re_err, &err_offset, 0);

        if (!pattern) {
            fprintf(stderr, "compile failed: %s\n", re_err);
            return 1;
        }

        pattern_extra = pcre_study(pattern, 0, (const char **)&re_err);
#else
        re_err = re_compile_pattern(match_data, strlen(match_data), &pattern);
        if (re_err) {
            fprintf(stderr, "regex compile: %s\n", re_err);
            return 1;
        }

        pattern.fastmap = (char*)malloc(256);
        if (re_compile_fastmap(&pattern)) {
            perror("fastmap compile failed");
            return 1;
        }
#endif

        match_func = &re_match_func;
    }

    return 0;
}

static inline uint8_t vlan_frame_count(u_char *p, uint16_t limit) {
  uint8_t *et = (uint8_t*)(p + 12);
  uint16_t ether_type = EXTRACT_16BITS(et);
  uint8_t count = 0;

  while ((void*)et < (void*)(p + limit) &&
         ether_type != ETHERTYPE_IP &&
         ether_type != ETHERTYPE_IPV6) {
      count++;
      et += VLANHDR_SIZE;
      ether_type = EXTRACT_16BITS(et);
  }

  return count;
}

void process(u_char *d, struct pcap_pkthdr *h, u_char *p) {
    uint8_t vlan_offset = include_vlan ? vlan_frame_count(p, h->caplen) * VLANHDR_SIZE : 0;

    struct ip      *ip4_pkt = (struct ip *)    (p + link_offset + vlan_offset);
#if USE_IPv6
    struct ip6_hdr *ip6_pkt = (struct ip6_hdr*)(p + link_offset + vlan_offset);
#endif

    uint32_t ip_ver;

    uint8_t  ip_proto = 0;
    uint32_t ip_hl    = 0;
    uint32_t ip_off   = 0;

    uint8_t  fragmented  = 0;
    uint16_t frag_offset = 0;
    uint32_t frag_id     = 0;

    char ip_src[INET6_ADDRSTRLEN + 1],
         ip_dst[INET6_ADDRSTRLEN + 1];

    unsigned char *data;
    uint32_t len = h->caplen - vlan_offset;

    seen_frames++;

#if HAVE_DLT_IEEE802_11_RADIO
    if (radiotap_present) {
        uint16_t radio_len = ((struct NGREP_rtaphdr_t *)(p))->it_len;
        ip4_pkt = (struct ip *)(p + link_offset + radio_len);
        len    -= radio_len;
    }
#endif

    ip_ver = ip4_pkt->ip_v;

    switch (ip_ver) {

        case 4: {
#if defined(AIX)
#undef ip_hl
            ip_hl       = ip4_pkt->ip_ff.ip_fhl * 4;
#else
            ip_hl       = ip4_pkt->ip_hl * 4;
#endif
            ip_proto    = ip4_pkt->ip_p;
            ip_off      = ntohs(ip4_pkt->ip_off);

            fragmented  = ip_off & (IP_MF | IP_OFFMASK);
            frag_offset = (fragmented) ? (ip_off & IP_OFFMASK) * 8 : 0;
            frag_id     = ntohs(ip4_pkt->ip_id);

            inet_ntop(AF_INET, (const void *)&ip4_pkt->ip_src, ip_src, sizeof(ip_src));
            inet_ntop(AF_INET, (const void *)&ip4_pkt->ip_dst, ip_dst, sizeof(ip_dst));
        } break;

#if USE_IPv6
        case 6: {
            ip_hl    = sizeof(struct ip6_hdr);
            ip_proto = ip6_pkt->ip6_nxt;

            if (ip_proto == IPPROTO_FRAGMENT) {
                struct ip6_frag *ip6_fraghdr;

                ip6_fraghdr = (struct ip6_frag *)((unsigned char *)(ip6_pkt) + ip_hl);
                ip_hl      += sizeof(struct ip6_frag);
                ip_proto    = ip6_fraghdr->ip6f_nxt;

                fragmented  = 1;
                frag_offset = ntohs(ip6_fraghdr->ip6f_offlg & IP6F_OFF_MASK);
                frag_id     = ntohl(ip6_fraghdr->ip6f_ident);
            }

            inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_src, ip_src, sizeof(ip_src));
            inet_ntop(AF_INET6, (const void *)&ip6_pkt->ip6_dst, ip_dst, sizeof(ip_dst));
        } break;
#endif
    }

    if (quiet < 1) {
        printf("#");
        fflush(stdout);
    }

    switch (ip_proto) {
        case IPPROTO_TCP: {
            struct tcphdr *tcp_pkt = (struct tcphdr *)((unsigned char *)(ip4_pkt) + ip_hl);
            uint16_t tcphdr_offset = (frag_offset) ? 0 : (tcp_pkt->th_off * 4);

            data = (unsigned char *)(tcp_pkt) + tcphdr_offset;
            len -= link_offset + ip_hl + tcphdr_offset;

            if ((int32_t)len < 0)
                len = 0;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, ntohs(tcp_pkt->th_sport), ntohs(tcp_pkt->th_dport), tcp_pkt->th_flags,
                        tcphdr_offset, fragmented, frag_offset, frag_id);
        } break;

        case IPPROTO_UDP: {
            struct udphdr *udp_pkt = (struct udphdr *)((unsigned char *)(ip4_pkt) + ip_hl);
            uint16_t udphdr_offset = (frag_offset) ? 0 : sizeof(*udp_pkt);

            data = (unsigned char *)(udp_pkt) + udphdr_offset;
            len -= link_offset + ip_hl + udphdr_offset;

            if ((int32_t)len < 0)
                len = 0;

            dump_packet(h, p, ip_proto, data, len, ip_src, ip_dst,
                        ntohs(udp_pkt->uh_sport), ntohs(udp_pkt->uh_dport), 0,
                        udphdr_offset, fragmented, frag_offset, frag_id);
        } break;

        case IPPROTO_ICMP: {
            struct icmp *icmp4_pkt   = (struct icmp *)((unsigned char *)(ip4_pkt) + ip_hl);
            uint16_t icmp4hdr_offset = (frag_offset) ? 0 : 4;

            data = (unsigned char *)(icmp4_pkt) + icmp4hdr_offset;
            len -= link_offset + ip_hl + icmp4hdr_offset;

            if ((int32_t)len < 0)
                len = 0;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, icmp4_pkt->icmp_type, icmp4_pkt->icmp_code, 0,
                        icmp4hdr_offset, fragmented, frag_offset, frag_id);
        } break;

#if USE_IPv6
        case IPPROTO_ICMPV6: {
            struct icmp6_hdr *icmp6_pkt = (struct icmp6_hdr *)((unsigned char *)(ip6_pkt) + ip_hl);
            uint16_t icmp6hdr_offset    = (frag_offset) ? 0 : 4;

            data = (unsigned char *)(icmp6_pkt) + icmp6hdr_offset;
            len -= link_offset + ip_hl + icmp6hdr_offset;

            if ((int32_t)len < 0)
                len = 0;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, icmp6_pkt->icmp6_type, icmp6_pkt->icmp6_code, 0,
                        icmp6hdr_offset, fragmented, frag_offset, frag_id);
        } break;
#endif

        case IPPROTO_IGMP: {
            struct igmp *igmp_pkt   = (struct igmp *)((unsigned char *)(ip4_pkt) + ip_hl);
            uint16_t igmphdr_offset = (frag_offset) ? 0 : 4;

            data = (unsigned char *)(igmp_pkt) + igmphdr_offset;
            len -= link_offset + ip_hl + igmphdr_offset;

            if ((int32_t)len < 0)
                len = 0;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, igmp_pkt->igmp_type, igmp_pkt->igmp_code, 0,
                        igmphdr_offset, fragmented, frag_offset, frag_id);
        } break;

        default: {
            data = (unsigned char *)(ip4_pkt) + ip_hl;
            len -= link_offset + ip_hl;

            if ((int32_t)len < 0)
                len = 0;

            dump_packet(h, p, ip_proto, data, len,
                        ip_src, ip_dst, 0, 0, 0,
                        0, fragmented, frag_offset, frag_id);
        } break;

    }

    if (max_matches && matches >= max_matches)
        clean_exit(0);

    if (match_after && keep_matching)
        keep_matching--;
}

void dump_packet(struct pcap_pkthdr *h, u_char *p, uint8_t proto, unsigned char *data, uint32_t len,
                 const char *ip_src, const char *ip_dst, uint16_t sport, uint16_t dport, uint8_t flags,
                 uint16_t hdr_offset, uint8_t frag, uint16_t frag_offset, uint32_t frag_id) {

    uint16_t match_size, match_index;

    if (!show_empty && len == 0)
        return;

    if (len > limitlen)
        len = limitlen;

    if ((len > 0 && match_func(data, len, &match_index, &match_size) == invert_match) && !keep_matching)
        return;

    if (!live_read && want_delay)
        dump_delay(h);

    {
        char ident;

        switch (proto) {
            case IPPROTO_TCP:    ident = TCP;     break;
            case IPPROTO_UDP:    ident = UDP;     break;
            case IPPROTO_ICMP:   ident = ICMP;    break;
            case IPPROTO_ICMPV6: ident = ICMPv6;  break;
            case IPPROTO_IGMP:   ident = IGMP;    break;
            default:             ident = UNKNOWN; break;
        }

        printf("\n%c", ident);
    }

    if (show_proto)
        printf("(%u)", proto);

    printf(" ");

    if (print_time)
        print_time(h);

    if ((proto == IPPROTO_TCP || proto == IPPROTO_UDP) && (sport || dport) && (hdr_offset || frag_offset == 0)) {
#if !defined(_WIN32)
        if (resolve_containers) {
            char src_formatted[128], dst_formatted[128];
            format_ip_with_container(ip_src, src_formatted, sizeof(src_formatted));
            format_ip_with_container(ip_dst, dst_formatted, sizeof(dst_formatted));
            printf("%s:%u -> %s:%u", src_formatted, sport, dst_formatted, dport);
        } else {
#endif
            printf("%s:%u -> %s:%u", ip_src, sport, ip_dst, dport);
#if !defined(_WIN32)
        }
#endif
    } else {
#if !defined(_WIN32)
        if (resolve_containers) {
            char src_formatted[128], dst_formatted[128];
            format_ip_with_container(ip_src, src_formatted, sizeof(src_formatted));
            format_ip_with_container(ip_dst, dst_formatted, sizeof(dst_formatted));
            printf("%s -> %s", src_formatted, dst_formatted);
        } else {
#endif
            printf("%s -> %s", ip_src, ip_dst);
#if !defined(_WIN32)
        }
#endif
    }

    if (proto == IPPROTO_TCP && flags)
        printf(" [%s%s%s%s%s%s%s%s]",
               (flags & TH_ACK) ? "A" : "",
               (flags & TH_SYN) ? "S" : "",
               (flags & TH_RST) ? "R" : "",
               (flags & TH_FIN) ? "F" : "",
               (flags & TH_URG) ? "U" : "",
               (flags & TH_PUSH)? "P" : "",
               (flags & TH_ECE) ? "E" : "",
               (flags & TH_CWR) ? "C" : "");

    switch (proto) {
        case IPPROTO_ICMP:
        case IPPROTO_ICMPV6:
        case IPPROTO_IGMP:
            printf(" %u:%u", sport, dport);
    }

    if (frag)
        printf(" %s%u@%u:%u",
               frag_offset?"+":"", frag_id, frag_offset, len);

    if (dump_single)
        printf(" ");
    else
        printf(" #%u\n", seen_frames);

    if (quiet < 3)
        dump_func(data, len, match_index, match_size);

    if (pd_dump)
        pcap_dump((u_char*)pd_dump, h, p);

#if USE_TCPKILL
    if (tcpkill_active)
        tcpkill_kill(h, p, link_offset, tcpkill_active);
#endif
}

int8_t re_match_func(unsigned char *data, uint32_t len, uint16_t *mindex, uint16_t *msize) {
#if USE_PCRE

    static int sub[2];
    switch(pcre_exec(pattern, 0, (char const *)data, (int32_t)len, 0, 0, 0, 0)) {
        case PCRE_ERROR_NULL:
        case PCRE_ERROR_BADOPTION:
        case PCRE_ERROR_BADMAGIC:
        case PCRE_ERROR_UNKNOWN_NODE:
        case PCRE_ERROR_NOMEMORY:
            perror("she's dead, jim\n");
            clean_exit(2);

        case PCRE_ERROR_NOMATCH:
            return 0;

        default:
            *mindex = sub[0];
            *msize  = sub[1] - sub[0];
    }
#else

    static struct re_registers regs;
    switch (re_search(&pattern, (char const *)data, (int32_t)len, 0, len, &regs)) {
        case -2:
            perror("she's dead, jim\n");
            clean_exit(2);

        case -1:
            return 0;

        default:
            *mindex = regs.start[0];
            *msize  = regs.end[0] - regs.start[0];
    }
#endif

    matches++;

    if (match_after && keep_matching != match_after)
        keep_matching = match_after;

    return 1;
}

int8_t bin_match_func(unsigned char *data, uint32_t len, uint16_t *mindex, uint16_t *msize) {
    int32_t stop = len - match_len;
    int32_t i    = 0;

    if (stop < 0)
        return 0;

    while (i <= stop)
        if (!memcmp(data+(i++), bin_data, match_len)) {
            matches++;

            if (match_after && keep_matching != match_after)
                keep_matching = match_after;

            *mindex = i - 1;
            *msize  = match_len;

            return 1;
        }

    return 0;
}

int8_t blank_match_func(unsigned char *data, uint32_t len, uint16_t *mindex, uint16_t *msize) {
    matches++;

    *mindex = 0;
    *msize  = 0;

    return 1;
}

void dump_byline(unsigned char *data, uint32_t len, uint16_t mindex, uint16_t msize) {
    if (len > 0) {
        const unsigned char *s      = data;
        uint8_t should_hilite       = (msize && enable_hilite);
        unsigned char *hilite_start = data + mindex;
        unsigned char *hilite_end   = hilite_start + msize;

        while (s < data + len) {
            if (should_hilite && s == hilite_start)
                printf("%s", ANSI_hilite);

            printf("%c", (*s == '\n' || isprint(*s)) ? *s : nonprint_char);
            s++;

            if (should_hilite && s == hilite_end)
                printf("%s", ANSI_off);
        }

        printf("\n");
    }
}

void dump_unwrapped(unsigned char *data, uint32_t len, uint16_t mindex, uint16_t msize) {
    if (len > 0) {
        const unsigned char *s      = data;
        uint8_t should_hilite       = (msize && enable_hilite);
        unsigned char *hilite_start = data + mindex;
        unsigned char *hilite_end   = hilite_start + msize;

        while (s < data + len) {
            if (should_hilite && s == hilite_start)
                printf("%s", ANSI_hilite);

            printf("%c", isprint(*s) ? *s : nonprint_char);
            s++;

            if (should_hilite && s == hilite_end)
                printf("%s", ANSI_off);
        }

        printf("\n");
    }
}

void dump_formatted(unsigned char *data, uint32_t len, uint16_t mindex, uint16_t msize) {
    if (len > 0) {
        uint8_t should_hilite = (msize && enable_hilite);
           unsigned char *str = data;
             uint8_t hiliting = 0;
                uint8_t width = show_hex ? 16 : (ws_col-5);
                   uint32_t i = 0,
                            j = 0;

        while (i < len) {
            printf("  ");

            if (show_hex) {
                for (j = 0; j < width; j++) {
                    if (should_hilite && (mindex <= (i+j) && (i+j) < mindex + msize)) {
                        hiliting = 1;
                        printf("%s", ANSI_hilite);
                    }

                    if (i + j < len)
                        printf("%02x ", str[j]);
                    else printf("   ");

                    if ((j+1) % (width/2) == 0)
                        printf("   ");

                    if (hiliting) {
                        hiliting = 0;
                        printf("%s", ANSI_off);
                    }
                }
            }

            for (j = 0; j < width; j++) {
                if (should_hilite && mindex <= (i+j) && (i+j) < mindex + msize) {
                    hiliting = 1;
                    printf("%s", ANSI_hilite);
                }

                if (i + j < len)
                    printf("%c", isprint(str[j]) ? str[j] : nonprint_char);
                else printf(" ");

                if (hiliting) {
                    hiliting = 0;
                    printf("%s", ANSI_off);
                }
            }

            str += width;
            i   += j;

            printf("\n");
        }
    }
}

char *get_filter_from_string(char *str) {
    const char *template = include_vlan ? BPF_TEMPLATE_USERSPEC_IP_VLAN : BPF_TEMPLATE_USERSPEC_IP;
    char *mine, *s;
    uint32_t len;

    if (!str || !*str)
        return NULL;

    len = (uint32_t)strlen(str);

    for (s = str; *s; s++)
        if (*s == '\r' || *s == '\n')
            *s = ' ';

    if (!(mine = (char*)malloc(len + strlen(template) + 1)))
        return NULL;

    memset(mine, 0, len + strlen(template) + 1);

    sprintf(mine, template, str);

    return mine;
}

char *get_filter_from_argv(char **argv) {
    const char *template = include_vlan ? BPF_TEMPLATE_USERSPEC_IP_VLAN : BPF_TEMPLATE_USERSPEC_IP;
    char **arg = argv, *theirs, *mine;
    char *from, *to;
    uint32_t len = 0;

    if (!*arg)
        return NULL;

    while (*arg)
        len += (uint32_t)strlen(*arg++) + 1;

    if (!(theirs = (char*)malloc(len + 1)) ||
        !(mine = (char*)malloc(len + strlen(template) + 1)))
        return NULL;

    memset(theirs, 0, len + 1);
    memset(mine, 0, len + strlen(template) + 1);

    arg = argv;
    to = theirs;

    while ((from = *arg++)) {
        while ((*to++ = *from++));
        *(to-1) = ' ';
    }

    sprintf(mine, template, theirs);

    free(theirs);
    return mine;
}


uint8_t strishex(char *str) {
    char *s;

    if ((s = strchr(str, 'x')))
        s++;
    else
        s = str;

    while (*s)
        if (!isxdigit(*s++))
            return 0;

    return 1;
}


void print_time_absolute(struct pcap_pkthdr *h) {
    struct tm *t = localtime((const time_t *)&h->ts.tv_sec);

    printf("%02u/%02u/%02u %02u:%02u:%02u.%06u ",
           t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour,
           t->tm_min, t->tm_sec, (uint32_t)h->ts.tv_usec);
}

void print_time_diff(struct pcap_pkthdr *h) {
    uint32_t secs, usecs;

    secs = h->ts.tv_sec - prev_ts.tv_sec;
    if (h->ts.tv_usec >= prev_ts.tv_usec)
        usecs = h->ts.tv_usec - prev_ts.tv_usec;
    else {
        secs--;
        usecs = 1000000 - (prev_ts.tv_usec - h->ts.tv_usec);
    }

    printf("+%u.%06u ", secs, usecs);

    prev_ts.tv_sec  = h->ts.tv_sec;
    prev_ts.tv_usec = h->ts.tv_usec;
}

void print_time_offset(struct pcap_pkthdr *h) {
    uint32_t secs, usecs;

    secs = h->ts.tv_sec - prev_ts.tv_sec;
    if (h->ts.tv_usec >= prev_ts.tv_usec)
        usecs = h->ts.tv_usec - prev_ts.tv_usec;
    else {
        secs--;
        usecs = 1000000 - (prev_ts.tv_usec - h->ts.tv_usec);
    }

    if (prev_ts.tv_sec == 0 && prev_ts.tv_usec == 0) {
        prev_ts.tv_sec  = h->ts.tv_sec;
        prev_ts.tv_usec = h->ts.tv_usec;
        secs  = 0;
        usecs = 0;
    }

    printf("+%u.%06u ", secs, usecs);
}

void dump_delay_proc_init(struct pcap_pkthdr *h) {
    dump_delay = &dump_delay_proc;

    prev_delay_ts.tv_sec  = h->ts.tv_sec;
    prev_delay_ts.tv_usec = h->ts.tv_usec;

    dump_delay(h);
}

void dump_delay_proc(struct pcap_pkthdr *h) {
    uint32_t secs, usecs;

    secs = h->ts.tv_sec - prev_delay_ts.tv_sec;
    if (h->ts.tv_usec >= prev_delay_ts.tv_usec)
        usecs = h->ts.tv_usec - prev_delay_ts.tv_usec;
    else {
        secs--;
        usecs = 1000000 - (prev_delay_ts.tv_usec - h->ts.tv_usec);
    }

#ifdef _WIN32
    {
        // grevious hack, yes, but windows sucks.  sorry. :(   --jordan
        if ((delay_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            perror("delay socket creation failed, disabling -D");
            Sleep(3000); // give them time to read the message
            want_delay = 0;
            return;
        }

        FD_ZERO(&delay_fds);
        FD_SET(delay_socket, &delay_fds);

        delay_tv.tv_sec  = secs;
        delay_tv.tv_usec = usecs;

        if (select(0, &delay_fds, 0, 0, &delay_tv) == -1)
            fprintf(stderr, "WSAGetLastError = %u\n", WSAGetLastError());

        closesocket(delay_socket);
        delay_socket = 0; // in case someone ^C's out of me
    }
#else
    sleep(secs);
    usleep(usecs);
#endif

    prev_delay_ts.tv_sec  = h->ts.tv_sec;
    prev_delay_ts.tv_usec = h->ts.tv_usec;
}

void update_windowsize(int32_t e) {
    if (e == 0 && ws_col_forced)

        ws_col = ws_col_forced;

    else if (!ws_col_forced) {

#if !defined(_WIN32)
        const struct winsize ws;

        if (!ioctl(0, TIOCGWINSZ, &ws)) {
            ws_row = ws.ws_row;
            ws_col = ws.ws_col;
        }
#else
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)) {
            ws_row = csbi.dwSize.Y;
            ws_col = csbi.dwSize.X;
        }
#endif
        else {
            ws_row = 24;
            ws_col = 80;
        }

    }
}

#if !defined(_WIN32) && USE_DROPPRIVS
void drop_privs(void) {
    struct passwd *pw;
    uid_t newuid;
    gid_t newgid;

    if ((getuid() || geteuid()) || dont_dropprivs)
        return;

    pw = getpwnam(DROPPRIVS_USER);
    if (!pw) {
        perror("attempt to drop privileges failed: getpwnam failed");
        clean_exit(2);
    }

    newgid = pw->pw_gid;
    newuid = pw->pw_uid;

    if (getgroups(0, NULL) > 0)
        if (setgroups(1, &newgid) == -1) {
            perror("attempt to drop privileges failed");
            clean_exit(2);
        }

    if (((getgid()  != newgid) && (setgid(newgid)  == -1)) ||
        ((getegid() != newgid) && (setegid(newgid) == -1)) ||
        ((getuid()  != newuid) && (setuid(newuid)  == -1)) ||
        ((geteuid() != newuid) && (seteuid(newuid) == -1))) {

        perror("attempt to drop privileges failed");
        clean_exit(2);
    }
}

#endif

void usage(void) {
    printf("usage: ngrep <-"
#if defined(_WIN32)
           "L"
#endif
           "hNXViwqpevxlDtTRME> <-IO pcap_dump> <-n num> <-d dev> <-A num>\n"
           "             <-s snaplen> <-S limitlen> <-W normal|byline|single|none> <-c cols>\n"
           "             <-P char> <-F file>"
#if USE_TCPKILL
           "             <-K count>"
#endif
           "\n"
           "             <match expression> <bpf filter>\n"
           "   -h  is help/usage\n"
           "   -V  is version information\n"
           "   -q  is be quiet (don't print packet reception hash marks)\n"
           "   -e  is show empty packets\n"
           "   -i  is ignore case\n"
           "   -v  is invert match\n"
           "   -R  is don't do privilege revocation logic\n"
           "   -x  is print in alternate hexdump format\n"
           "   -X  is interpret match expression as hexadecimal\n"
           "   -w  is word-regex (expression must match as a word)\n"
           "   -p  is don't go into promiscuous mode\n"
           "   -l  is make stdout line buffered\n"
           "   -D  is replay pcap_dumps with their recorded time intervals\n"
           "   -t  is print timestamp every time a packet is matched\n"
           "   -T  is print delta timestamp every time a packet is matched\n"
           "         specify twice for delta from first match\n"
           "   -M  is don't do multi-line match (do single-line match instead)\n"
           "   -I  is read packet stream from pcap format file pcap_dump\n"
           "   -O  is dump matched packets in pcap format to pcap_dump\n"
           "   -n  is look at only num packets\n"
           "   -A  is dump num packets after a match\n"
           "   -s  is set the bpf caplen\n"
           "   -S  is set the limitlen on matched packets\n"
           "   -W  is set the dump format (normal, byline, single, none)\n"
           "   -c  is force the column width to the specified size\n"
           "   -P  is set the non-printable display char to what is specified\n"
           "   -F  is read the bpf filter from the specified file\n"
           "   -N  is show sub protocol number\n"
#if defined(_WIN32)
           "   -d  is use specified device (index) instead of the pcap default\n"
           "   -L  is show the winpcap device list index\n"
#else
           "   -d  is use specified device instead of the pcap default\n"
#endif
#if USE_TCPKILL
           "   -K  is send N packets to kill observed connections\n"
#endif
           "   -E  is resolve container names for IP addresses (optional: ttl=30,timeout=1)\n"
           "");

    exit(2);
}


void version(void) {
    printf("ngrep: V%s, %s\n", VERSION, pcap_lib_version());
    exit(0);
}


void clean_exit(int32_t sig) {
    struct pcap_stat s;

    signal(SIGINT,   SIG_IGN);
    signal(SIGABRT,  SIG_IGN);
#if !defined(_WIN32)
    signal(SIGQUIT,  SIG_IGN);
    signal(SIGPIPE,  SIG_IGN);
    signal(SIGWINCH, SIG_IGN);
#endif

    if (quiet < 1 && sig >= 0)
        printf("exit\n");

#if USE_PCRE
    if (pattern)       pcre_free(pattern);
    if (pattern_extra) pcre_free(pattern_extra);
#else
    if (pattern.translate) free(pattern.translate);
    if (pattern.fastmap)   free(pattern.fastmap);
#endif

    if (bin_data)          free(bin_data);

    /* We used to report pcap_stats; but PCAP manpage says pcap_stats "may or
       may not" be accurate. So useless. :-( And confusing for a user to see
       counts not match what ngrep thinks. */
    if (quiet < 1 && sig >= 0 && !read_file)
        printf("%u received, %u matched\n", seen_frames, matches);

    if (pd)           pcap_close(pd);
    if (pd_dumppcap)  pcap_close(pd_dumppcap);
    if (pd_dump)      pcap_dump_close(pd_dump);

#if defined(_WIN32)
    if (delay_socket) closesocket(delay_socket);
    if (want_delay)   WSACleanup();
    if (usedev)       free(usedev);
#endif

    exit(matches ? 0 : 1);
}

#if defined(_WIN32)
int8_t win32_initwinsock(void) {
    WORD wVersionRequested = MAKEWORD(2, 0);
    WSADATA wsaData;

    if (WSAStartup(wVersionRequested, &wsaData)) {
        perror("unable to initialize winsock");
        return 0;
    }

    // we want at least major version 2
    if (LOBYTE(wsaData.wVersion) < 2) {
        fprintf(stderr, "unable to find winsock 2.0 or greater (found %u.%u)\n",
                LOBYTE(wsaData.wVersion), HIBYTE(wsaData.wVersion));
        WSACleanup();
        return 0;
    }

    return 1;
}

void win32_listdevices(void) {
    uint32_t i = 0;
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror("unable to enumerate device list");
        clean_exit(2);
    }

    printf("idx\tdev\n");
    printf("---\t---\n");

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%2u:\t%s", ++i, d->name);

        if (d->description)
            printf(" (%s)\n", d->description);
    }

    pcap_freealldevs(alldevs);
}

char *win32_usedevice(const char *index) {
    int32_t idx = atoi(index), i = 0;
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;

    if (idx <= 0) {
        perror("invalid device index");
        clean_exit(2);
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror("unable to enumerate devices");
        clean_exit(2);
    }

    for (d = alldevs; d != NULL && i != idx; d = d->next)
        if (++i == idx)
            dev = _strdup(d->name);

    if (i <= 0) {
        perror("no known devices");
        clean_exit(2);
    }

    if (i != idx) {
        perror("unknown device specified");
        clean_exit(2);
    }

    pcap_freealldevs(alldevs);

    return dev;
}

char *win32_choosedevice(void) {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        perror("unable to enumerate devices");
        clean_exit(2);
    }

    for (d = alldevs; d != NULL; d = d->next)
        if ((d->addresses) && (d->addresses->addr))
            dev = _strdup(d->name);

    pcap_freealldevs(alldevs);

    if (!dev)
        dev = pcap_lookupdev(errbuf);

    return dev;
}
#endif

/*
 * Container Resolution Functions
 */

static const char* lookup_container_name(const char* ip_addr) {
    if (!resolve_containers || !ip_addr) {
        return NULL;
    }
    
    time_t now = time(NULL);
    
    /* Check if cache needs refresh */
    if (now - g_container_cache.last_refresh > container_cache_ttl) {
        refresh_container_cache();
    }
    
    /* Cleanup expired entries */
    cleanup_expired_cache_entries();
    
    /* Search cache for IP address */
    for (uint32_t i = 0; i < g_container_cache.count; i++) {
        if (strcmp(g_container_cache.entries[i].ip_addr, ip_addr) == 0) {
            /* Update last seen timestamp */
            g_container_cache.entries[i].last_seen = now;
            return g_container_cache.entries[i].container_name;
        }
    }
    
    return NULL;
}

static int refresh_container_cache(void) {
    if (!resolve_containers) {
        return 0;
    }
    
    /* Clear current cache */
    memset(&g_container_cache, 0, sizeof(g_container_cache));
    g_container_cache.last_refresh = time(NULL);
    
    /* Discover containers via Docker/Podman APIs */
    return discover_container_ips_via_netlink();
}

static void cleanup_expired_cache_entries(void) {
    time_t now = time(NULL);
    uint32_t write_idx = 0;
    
    for (uint32_t read_idx = 0; read_idx < g_container_cache.count; read_idx++) {
        if (now - g_container_cache.entries[read_idx].last_seen <= container_cache_ttl) {
            if (write_idx != read_idx) {
                g_container_cache.entries[write_idx] = g_container_cache.entries[read_idx];
            }
            write_idx++;
        }
    }
    
    g_container_cache.count = write_idx;
}

static int discover_containers_via_netns(void) {
    DIR *proc_dir;
    struct dirent *entry;
    char path[256];
    int pid;
    struct netns_info netns_info;
    
    proc_dir = opendir("/proc");
    if (!proc_dir) {
        return -1;
    }
    
    while ((entry = readdir(proc_dir)) != NULL && g_container_cache.count < MAX_CONTAINERS) {
        /* Check if directory name is a PID */
        pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }
        
        /* Parse container information from this process */
        if (parse_container_from_proc(pid, &netns_info) == 0) {
            /* Try to get IP addresses for this container's network namespace */
            /* This is a simplified implementation - we'll enhance it in the next phase */
            if (strlen(netns_info.container_name) > 0) {
                snprintf(g_container_cache.entries[g_container_cache.count].container_name,
                        MAX_CONTAINER_NAME, "%s", netns_info.container_name);
                snprintf(g_container_cache.entries[g_container_cache.count].ip_addr,
                        MAX_IP_ADDR_LEN, "0.0.0.0"); /* Placeholder - will be filled by netlink */
                g_container_cache.entries[g_container_cache.count].netns_id = netns_info.netns_id;
                g_container_cache.entries[g_container_cache.count].last_seen = time(NULL);
                g_container_cache.count++;
            }
        }
    }
    
    closedir(proc_dir);
    return 0;
}

static int parse_container_from_proc(int pid, struct netns_info *info) {
    char path[256];
    char cmdline[1024];
    char cgroup[1024];
    FILE *file;
    struct stat ns_stat;
    
    if (!info) {
        return -1;
    }
    
    memset(info, 0, sizeof(*info));
    info->pid = pid;
    
    /* Get network namespace ID */
    snprintf(path, sizeof(path), "/proc/%d/ns/net", pid);
    if (stat(path, &ns_stat) == 0) {
        info->netns_id = (uint32_t)ns_stat.st_ino;
    }
    
    /* Read command line */
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    file = fopen(path, "r");
    if (file) {
        if (fgets(cmdline, sizeof(cmdline), file)) {
            /* Look for container runtime signatures */
            if (strstr(cmdline, "docker") || strstr(cmdline, "containerd") || 
                strstr(cmdline, "podman") || strstr(cmdline, "conmon")) {
                
                /* Extract container name/ID from cmdline */
                char *name_start = strstr(cmdline, "--name");
                if (name_start) {
                    name_start += 6;
                    while (*name_start == ' ' || *name_start == '=') name_start++;
                    char *name_end = strchr(name_start, ' ');
                    if (name_end) *name_end = '\0';
                    strncpy(info->container_name, name_start, MAX_CONTAINER_NAME - 1);
                }
            }
        }
        fclose(file);
    }
    
    /* Read cgroup for container ID if name not found */
    if (strlen(info->container_name) == 0) {
        snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
        file = fopen(path, "r");
        if (file) {
            while (fgets(cgroup, sizeof(cgroup), file)) {
                /* Look for container ID in cgroup path */
                char *container_id = strstr(cgroup, "/docker/");
                if (!container_id) container_id = strstr(cgroup, "/podman/");
                if (!container_id) container_id = strstr(cgroup, "/system.slice/docker-");
                
                if (container_id) {
                    container_id = strrchr(cgroup, '/');
                    if (container_id) {
                        container_id++; /* Skip the '/' */
                        char *dot = strchr(container_id, '.');
                        if (dot) *dot = '\0';
                        char *newline = strchr(container_id, '\n');
                        if (newline) *newline = '\0';
                        
                        /* Use first 12 chars of container ID as name */
                        strncpy(info->container_name, container_id, 
                               MIN(12, MAX_CONTAINER_NAME - 1));
                        break;
                    }
                }
            }
            fclose(file);
        }
    }
    
    return (strlen(info->container_name) > 0) ? 0 : -1;
}

static int discover_container_ips_via_netlink(void) {
    FILE *fp;
    char line[512];
    char cmd[512];
    uint32_t cache_idx = 0;
    
    /* Try Docker first */
    fp = popen("docker ps --format '{{.Names}}' --no-trunc 2>/dev/null", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp) && cache_idx < MAX_CONTAINERS) {
            /* Remove newline */
            line[strcspn(line, "\n")] = '\0';
            
            if (strlen(line) > 0) {
                /* For each container, get IP addresses */
                snprintf(cmd, sizeof(cmd), 
                        "docker inspect %s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null",
                        line);
                
                FILE *inspect_fp = popen(cmd, "r");
                if (inspect_fp) {
                    char ips[256];
                    if (fgets(ips, sizeof(ips), inspect_fp)) {
                        char *ip = strtok(ips, " \n");
                        while (ip && cache_idx < MAX_CONTAINERS) {
                            if (strlen(ip) > 0 && strcmp(ip, "") != 0) {
                                strncpy(g_container_cache.entries[cache_idx].container_name, 
                                       line, MAX_CONTAINER_NAME - 1);
                                g_container_cache.entries[cache_idx].container_name[MAX_CONTAINER_NAME - 1] = '\0';
                                
                                strncpy(g_container_cache.entries[cache_idx].ip_addr, 
                                       ip, MAX_IP_ADDR_LEN - 1);
                                g_container_cache.entries[cache_idx].ip_addr[MAX_IP_ADDR_LEN - 1] = '\0';
                                
                                g_container_cache.entries[cache_idx].last_seen = time(NULL);
                                cache_idx++;
                            }
                            ip = strtok(NULL, " \n");
                        }
                    }
                    pclose(inspect_fp);
                }
            }
        }
        pclose(fp);
    }
    
    /* Try Podman if Docker didn't find containers or isn't available */
    if (cache_idx == 0) {
        fp = popen("podman ps --format '{{.Names}}' --no-trunc 2>/dev/null", "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp) && cache_idx < MAX_CONTAINERS) {
                /* Remove newline */
                line[strcspn(line, "\n")] = '\0';
                
                if (strlen(line) > 0) {
                    snprintf(cmd, sizeof(cmd), 
                            "podman inspect %s --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null",
                            line);
                    
                    FILE *inspect_fp = popen(cmd, "r");
                    if (inspect_fp) {
                        char ips[256];
                        if (fgets(ips, sizeof(ips), inspect_fp)) {
                            char *ip = strtok(ips, " \n");
                            while (ip && cache_idx < MAX_CONTAINERS) {
                                if (strlen(ip) > 0 && strcmp(ip, "") != 0) {
                                    strncpy(g_container_cache.entries[cache_idx].container_name, 
                                           line, MAX_CONTAINER_NAME - 1);
                                    g_container_cache.entries[cache_idx].container_name[MAX_CONTAINER_NAME - 1] = '\0';
                                    
                                    strncpy(g_container_cache.entries[cache_idx].ip_addr, 
                                           ip, MAX_IP_ADDR_LEN - 1);
                                    g_container_cache.entries[cache_idx].ip_addr[MAX_IP_ADDR_LEN - 1] = '\0';
                                    
                                    g_container_cache.entries[cache_idx].last_seen = time(NULL);
                                    cache_idx++;
                                }
                                ip = strtok(NULL, " \n");
                            }
                        }
                        pclose(inspect_fp);
                    }
                }
            }
            pclose(fp);
        }
    }
    
    g_container_cache.count = cache_idx;
    return cache_idx > 0 ? 0 : -1;
}

static int send_netlink_request(int sock, int type, int family) {
    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;
    
    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = type;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    
    req.ifa.ifa_family = family;
    
    return send(sock, &req, req.nlh.nlmsg_len, 0);
}

static int parse_netlink_response(char* buf, int len) {
    struct nlmsghdr *nlh;
    struct ifaddrmsg *ifa;
    struct rtattr *rta;
    int rtl;
    char ip_str[INET6_ADDRSTRLEN];
    struct stat netns_stat;
    char netns_path[256];
    uint32_t netns_id;
    
    for (nlh = (struct nlmsghdr*)buf; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_DONE) {
            return -1; /* End of messages */
        }
        
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        
        if (nlh->nlmsg_type != RTM_NEWADDR) {
            continue;
        }
        
        ifa = NLMSG_DATA(nlh);
        rta = IFA_RTA(ifa);
        rtl = IFA_PAYLOAD(nlh);
        
        /* Get network namespace for this interface */
        snprintf(netns_path, sizeof(netns_path), "/proc/self/task/%d/ns/net", nlh->nlmsg_pid);
        if (stat(netns_path, &netns_stat) == 0) {
            netns_id = (uint32_t)netns_stat.st_ino;
        } else {
            continue;
        }
        
        /* Parse address attributes */
        for (; RTA_OK(rta, rtl); rta = RTA_NEXT(rta, rtl)) {
            if (rta->rta_type == IFA_ADDRESS || rta->rta_type == IFA_LOCAL) {
                void *addr_data = RTA_DATA(rta);
                
                if (ifa->ifa_family == AF_INET) {
                    struct in_addr *addr = (struct in_addr*)addr_data;
                    inet_ntop(AF_INET, addr, ip_str, INET_ADDRSTRLEN);
                }
#if USE_IPv6
                else if (ifa->ifa_family == AF_INET6) {
                    struct in6_addr *addr = (struct in6_addr*)addr_data;
                    inet_ntop(AF_INET6, addr, ip_str, INET6_ADDRSTRLEN);
                }
#endif
                else {
                    continue;
                }
                
                /* Find container with matching netns_id and update IP */
                for (uint32_t i = 0; i < g_container_cache.count; i++) {
                    if (g_container_cache.entries[i].netns_id == netns_id) {
                        /* Skip loopback and link-local addresses */
                        if (strcmp(ip_str, "127.0.0.1") == 0 || 
                            strncmp(ip_str, "169.254.", 8) == 0 ||
                            strncmp(ip_str, "fe80:", 5) == 0) {
                            continue;
                        }
                        
                        strncpy(g_container_cache.entries[i].ip_addr, ip_str, MAX_IP_ADDR_LEN - 1);
                        g_container_cache.entries[i].ip_addr[MAX_IP_ADDR_LEN - 1] = '\0';
                        break;
                    }
                }
            }
        }
    }
    
    return 0;
}

static void format_ip_with_container(const char* ip_addr, char* output, size_t output_size) {
#if !defined(_WIN32)
    const char* container_name;
    
    if (!ip_addr || !output || output_size == 0) {
        if (output && output_size > 0) {
            output[0] = '\0';
        }
        return;
    }
    
    /* Try to resolve container name */
    container_name = lookup_container_name(ip_addr);
    
    if (container_name && strlen(container_name) > 0) {
        /* Format as: container_name(ip_addr) */
        snprintf(output, output_size, "%s(%s)", container_name, ip_addr);
    } else {
        /* Just use the IP address */
        strncpy(output, ip_addr, output_size - 1);
        output[output_size - 1] = '\0';
    }
#else
    /* On Windows, just copy the IP address */
    if (ip_addr && output && output_size > 0) {
        strncpy(output, ip_addr, output_size - 1);
        output[output_size - 1] = '\0';
    }
#endif
}

#if defined(_WIN32)
/* Windows stub implementations for container resolution functions */

/* Forward declaration for Windows */
struct netns_info {
    uint32_t netns_id;
    int pid;
    char container_id[65];
    char container_name[64];
};

static const char* lookup_container_name(const char* ip_addr) {
    (void)ip_addr; /* Suppress unused parameter warning */
    return NULL;
}

static int refresh_container_cache(void) {
    return 0;
}

static int discover_containers_via_netns(void) {
    return 0;
}

static int parse_container_from_proc(int pid, struct netns_info *info) {
    (void)pid;
    (void)info;
    return -1;
}

static int get_netns_for_ip(const char* ip_addr, uint32_t* netns_id) {
    (void)ip_addr;
    (void)netns_id;
    return -1;
}

static void cleanup_expired_cache_entries(void) {
    /* Do nothing on Windows */
}

static int discover_container_ips_via_netlink(void) {
    return 0;
}

static int parse_netlink_response(char* buf, int len) {
    (void)buf;
    (void)len;
    return -1;
}

static int send_netlink_request(int sock, int type, int family) {
    (void)sock;
    (void)type;
    (void)family;
    return -1;
}
#endif
