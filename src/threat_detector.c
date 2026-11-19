
#include <stdio.h>
#include <string.h>

// Function declarations from our algorithms
int naive_search(const char *text, const char *pattern);
int rabin_karp_search(const char *text, const char *pattern);
int kmp_search(const char *text, const char *pattern);
int finite_automaton_search(const char *text, const char *pattern);

// Function pointer for selecting an algorithm
typedef int (*SearchFunction)(const char *, const char *);

// Suspicious event patterns
const char *suspicious_patterns[] = {
    "LOGIN_FAILED",
    "UNAUTHORIZED_ACCESS",
    "MALWARE",
    "PORT_SCAN"
};

#define PATTERN_COUNT 4

// Check whether an event is suspicious using a selected algorithm
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

// Detect threats using the selected algorithm
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
    int suspicious_count = 0;

    printf("\n----- THREAT DETECTION -----\n");

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

            printf("\n[WARNING] Suspicious activity detected!\n");
            printf("IP Address: %s\n", ip);
            printf("Event: %s\n", event);

            if (username != NULL) {
                printf("Username: %s\n", username);
            }

            printf("Log: %s", original_line);
        }
    }

    printf("\nTotal suspicious entries: %d\n", suspicious_count);

    fclose(file);
}

// Keep the original function compatible with existing main.c
// By default, this version uses Naive String Matching.
void detect_threats(const char *filename) {
    detect_threats_with_algorithm(filename, naive_search);
}
