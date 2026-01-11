/*
 * Copyright (c) 2025  Matej Bellus <matej.bellus@gmail.com>
 *
 * Please refer to the LICENSE file for more information.
 *
 * Container name resolution for Docker/Podman containers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "container-resolution.h"

/*
 * Container Resolution Data Structures
 */

#define MAX_CONTAINERS 1024
#define MAX_CONTAINER_NAME 64
#define MAX_IP_ADDR_LEN 64
#define DEFAULT_CACHE_TTL 30

struct container_entry {
    char ip_addr[MAX_IP_ADDR_LEN];
    char container_name[MAX_CONTAINER_NAME];
    time_t last_seen;
};

struct container_cache {
    struct container_entry entries[MAX_CONTAINERS];
    uint32_t count;
    time_t last_refresh;
};

/* Global container cache */
static struct container_cache g_container_cache = {0};
static uint32_t cache_ttl = DEFAULT_CACHE_TTL;

/* Forward declarations for internal functions */
static const char* lookup_container_name(const char* ip_addr);
static void cleanup_expired_cache_entries(void);
static int discover_containers_via_cli(void);

/*
 * Public API Implementation
 */

int container_resolution_init(void) {
    /* Clear current cache */
    memset(&g_container_cache, 0, sizeof(g_container_cache));
    g_container_cache.last_refresh = time(NULL);

    /* Discover containers via Docker/Podman CLI commands */
    return discover_containers_via_cli();
}

int container_refresh_cache(void) {
    return container_resolution_init();
}

void container_cleanup(void) {
    memset(&g_container_cache, 0, sizeof(g_container_cache));
}

void container_format_ip(const char* ip_addr, char* output, size_t output_size) {
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
}

/*
 * Internal Implementation
 */

static const char* lookup_container_name(const char* ip_addr) {
    if (!ip_addr) {
        return NULL;
    }

    time_t now = time(NULL);

    /* Check if cache needs refresh */
    if (now - g_container_cache.last_refresh > cache_ttl) {
        container_refresh_cache();
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

static void cleanup_expired_cache_entries(void) {
    time_t now = time(NULL);
    uint32_t write_idx = 0;

    for (uint32_t read_idx = 0; read_idx < g_container_cache.count; read_idx++) {
        if (now - g_container_cache.entries[read_idx].last_seen <= cache_ttl) {
            if (write_idx != read_idx) {
                g_container_cache.entries[write_idx] = g_container_cache.entries[read_idx];
            }
            write_idx++;
        }
    }

    g_container_cache.count = write_idx;
}

static int discover_containers_via_cli(void) {
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
