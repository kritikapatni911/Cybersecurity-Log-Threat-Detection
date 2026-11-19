
#include <stdio.h>
#include <string.h>

// ==========================================
// 1. ALGORITHM FUNCTION DECLARATIONS
// ==========================================

int naive_search(const char *text, const char *pattern);
int rabin_karp_search(const char *text, const char *pattern);
int kmp_search(const char *text, const char *pattern);
int finite_automaton_search(const char *text, const char *pattern);

typedef int (*SearchFunction)(const char *, const char *);

// ==========================================
// 2. SUSPICIOUS EVENT PATTERNS
// ==========================================

#define PATTERN_COUNT 4
#define MAX_IPS 100

const char *suspicious_patterns[PATTERN_COUNT] = {
    "LOGIN_FAILED",
    "UNAUTHORIZED_ACCESS",
    "MALWARE",
    "PORT_SCAN"
};

// ==========================================
// 3. IP ADDRESS COUNTER
// ==========================================

struct IPCount {
    char ip[64];
    int count;
};

// ==========================================
// 4. CHECK SUSPICIOUS EVENTS
// ==========================================

int is_suspicious_event(
    const char *event,
    SearchFunction search
) {
    for (int i = 0; i < PATTERN_COUNT; i++) {
        if (search(event, suspicious_patterns[i]) > 0) {
            return 1;
        }
    }

    return 0;
}

// ==========================================
// 5. GET THREAT SEVERITY
// ==========================================

const char *get_severity(
    const char *event,
    int ip_count
) {
    if (strcmp(event, "MALWARE") == 0) {
        return "CRITICAL";
    }

    if (strcmp(event, "UNAUTHORIZED_ACCESS") == 0) {
        return "HIGH";
    }

    if (strcmp(event, "PORT_SCAN") == 0) {
        return "HIGH";
    }

    if (strcmp(event, "LOGIN_FAILED") == 0) {
        if (ip_count >= 5) {
            return "HIGH";
        }

        return "MEDIUM";
    }

    return "LOW";
}

// ==========================================
// 6. FIND IP ADDRESS COUNT
// ==========================================

int find_ip_count(
    struct IPCount ip_list[],
    int ip_total,
    const char *ip
) {
    for (int i = 0; i < ip_total; i++) {
        if (strcmp(ip_list[i].ip, ip) == 0) {
            return ip_list[i].count;
        }
    }

    return 0;
}

// ==========================================
// 7. MAIN THREAT DETECTION FUNCTION
// ==========================================

void detect_threats_with_algorithm(
    const char *filename,
    SearchFunction search
) {
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        printf("Error: Could not open log file.\n");
        return;
    }

    char line[1024];
    char original_line[1024];

    struct IPCount ip_list[MAX_IPS];

    int ip_total = 0;
    int suspicious_count = 0;

    // --------------------------------------
    // FIRST PASS: COUNT SUSPICIOUS EVENTS
    // FROM EACH IP ADDRESS
    // --------------------------------------

    while (fgets(line, sizeof(line), file) != NULL) {

        char *timestamp = strtok(line, ",\r\n");
        char *ip = strtok(NULL, ",\r\n");
        char *event = strtok(NULL, ",\r\n");

        if (timestamp == NULL || ip == NULL || event == NULL) {
            continue;
        }

        if (is_suspicious_event(event, search)) {

            int found = 0;

            for (int i = 0; i < ip_total; i++) {

                if (strcmp(ip_list[i].ip, ip) == 0) {
                    ip_list[i].count++;
                    found = 1;
                    break;
                }
            }

            if (!found && ip_total < MAX_IPS) {

                strncpy(ip_list[ip_total].ip, ip,
                        sizeof(ip_list[ip_total].ip) - 1);

                ip_list[ip_total].ip[
                    sizeof(ip_list[ip_total].ip) - 1
                ] = '\0';

                ip_list[ip_total].count = 1;

                ip_total++;
            }
        }
    }

    // --------------------------------------
    // SECOND PASS: DISPLAY DETECTED THREATS
    // --------------------------------------

    rewind(file);

    printf("\n====================================\n");
    printf("       THREAT DETECTION RESULTS\n");
    printf("====================================\n");

    while (fgets(line, sizeof(line), file) != NULL) {

        strcpy(original_line, line);

        char *timestamp = strtok(line, ",\r\n");
        char *ip = strtok(NULL, ",\r\n");
        char *event = strtok(NULL, ",\r\n");
        char *username = strtok(NULL, ",\r\n");

        if (timestamp == NULL || ip == NULL || event == NULL) {
            continue;
        }

        if (is_suspicious_event(event, search)) {

            suspicious_count++;

            int count = find_ip_count(
                ip_list,
                ip_total,
                ip
            );

            const char *severity = get_severity(event, count);

            printf("\n[WARNING] Suspicious activity detected!\n");

            printf("Timestamp: %s\n", timestamp);
            printf("IP Address: %s\n", ip);
            printf("Event: %s\n", event);

            if (username != NULL) {
                printf("Username: %s\n", username);
            }

            printf("IP Suspicious Event Count: %d\n", count);
            printf("Severity: %s\n", severity);

            printf("Log: %s", original_line);
        }
    }

    printf("\n====================================\n");
    printf("Total suspicious entries: %d\n", suspicious_count);
    printf("====================================\n");

    fclose(file);
}

// ==========================================
// 8. ORIGINAL FUNCTION COMPATIBILITY
// ==========================================

void detect_threats(const char *filename) {
    detect_threats_with_algorithm(filename, naive_search);
}
