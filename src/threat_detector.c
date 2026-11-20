
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE 1024
#define MAX_IPS 1000
#define IP_SIZE 50
#define USER_SIZE 100
#define EVENT_SIZE 100
#define TIME_SIZE 100

// String matching algorithm declarations
int naive_search(const char *text, const char *pattern);
int rabin_karp_search(const char *text, const char *pattern);
int kmp_search(const char *text, const char *pattern);
int finite_automaton_search(const char *text, const char *pattern);

// Function pointer type
typedef int (*SearchFunction)(const char *, const char *);

// Suspicious event signatures
const char *signatures[] = {
    "LOGIN_FAILED",
    "UNAUTHORIZED_ACCESS",
    "MALWARE",
    "PORT_SCAN"
};

#define SIGNATURE_COUNT 4

// Store suspicious event counts for each IP
typedef struct {
    char ip[IP_SIZE];
    int count;
} IPRecord;

IPRecord ip_records[MAX_IPS];
int ip_record_count = 0;


// Parse one CSV log line
int parse_log_line(
    char *line,
    char *timestamp,
    char *ip,
    char *event,
    char *username
) {
    char *token;

    token = strtok(line, ",");
    if (token == NULL) return 0;
    snprintf(timestamp, TIME_SIZE, "%s", token);

    token = strtok(NULL, ",");
    if (token == NULL) return 0;
    snprintf(ip, IP_SIZE, "%s", token);

    token = strtok(NULL, ",");
    if (token == NULL) return 0;
    snprintf(event, EVENT_SIZE, "%s", token);

    token = strtok(NULL, ",\r\n");
    if (token == NULL) return 0;
    snprintf(username, USER_SIZE, "%s", token);

    return 1;
}


// Check whether an event is suspicious
int is_suspicious_event(
    const char *event,
    SearchFunction search
) {
    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        if (search(event, signatures[i]) > 0) {
            return 1;
        }
    }

    return 0;
}


// Find or create an IP record
int find_ip_record(const char *ip) {
    for (int i = 0; i < ip_record_count; i++) {
        if (strcmp(ip_records[i].ip, ip) == 0) {
            return i;
        }
    }

    if (ip_record_count >= MAX_IPS) {
        return -1;
    }

    snprintf(
        ip_records[ip_record_count].ip,
        IP_SIZE,
        "%s",
        ip
    );

    ip_records[ip_record_count].count = 0;

    ip_record_count++;

    return ip_record_count - 1;
}


// Get the suspicious event count for an IP
int get_ip_count(const char *ip) {
    for (int i = 0; i < ip_record_count; i++) {
        if (strcmp(ip_records[i].ip, ip) == 0) {
            return ip_records[i].count;
        }
    }

    return 0;
}


// Assign severity based on project rules
const char *get_severity(const char *event, int ip_count) {

    if (strcmp(event, "MALWARE") == 0) {
        return "CRITICAL";
    }

    if (
        strcmp(event, "UNAUTHORIZED_ACCESS") == 0 ||
        strcmp(event, "PORT_SCAN") == 0
    ) {
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


// First pass: count suspicious events for every IP
void count_suspicious_events(
    const char *filename,
    SearchFunction search
) {
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        printf("Error: Cannot open log file: %s\n", filename);
        return;
    }

    char line[MAX_LINE];
    char timestamp[TIME_SIZE];
    char ip[IP_SIZE];
    char event[EVENT_SIZE];
    char username[USER_SIZE];

    ip_record_count = 0;

    while (fgets(line, sizeof(line), file)) {

        char copy[MAX_LINE];
        snprintf(copy, sizeof(copy), "%s", line);

        if (!parse_log_line(
            copy, timestamp, ip, event, username
        )) {
            continue;
        }

        if (is_suspicious_event(event, search)) {

            int index = find_ip_record(ip);

            if (index >= 0) {
                ip_records[index].count++;
            }
        }
    }

    fclose(file);
}


// Second pass: print and export suspicious events
void export_threat_report(
    const char *filename,
    SearchFunction search
) {
    FILE *file = fopen(filename, "r");

    if (file == NULL) {
        printf("Error: Cannot open log file: %s\n", filename);
        return;
    }

    FILE *report = fopen("output/threat_report.csv", "w");

    if (report == NULL) {
        printf("Error: Could not create output/threat_report.csv\n");
        printf("Check that the output folder exists.\n");
        fclose(file);
        return;
    }

    // Write CSV column headings
    fprintf(
        report,
        "Timestamp,IP,Event,Username,IP_Event_Count,Severity\n"
    );

    char line[MAX_LINE];
    char timestamp[TIME_SIZE];
    char ip[IP_SIZE];
    char event[EVENT_SIZE];
    char username[USER_SIZE];

    int total_suspicious = 0;

    printf("\n========== THREAT DETECTION REPORT ==========\n");

    while (fgets(line, sizeof(line), file)) {

        char copy[MAX_LINE];
        snprintf(copy, sizeof(copy), "%s", line);

        if (!parse_log_line(
            copy, timestamp, ip, event, username
        )) {
            continue;
        }

        if (is_suspicious_event(event, search)) {

            int ip_count = get_ip_count(ip);

            const char *severity = get_severity(event, ip_count);

            // Display threat in terminal
            printf("\n[WARNING] Suspicious activity detected!\n");
            printf("Timestamp: %s\n", timestamp);
            printf("IP Address: %s\n", ip);
            printf("Event: %s\n", event);
            printf("Username: %s\n", username);
            printf("IP Suspicious Event Count: %d\n", ip_count);
            printf("Severity: %s\n", severity);

            // Export threat to CSV file
            fprintf(
                report,
                "%s,%s,%s,%s,%d,%s\n",
                timestamp,
                ip,
                event,
                username,
                ip_count,
                severity
            );

            total_suspicious++;
        }
    }

    printf("\n=============================================\n");
    printf("Total suspicious entries: %d\n", total_suspicious);
    printf("Report saved to: output/threat_report.csv\n");
    printf("=============================================\n");

    fclose(file);
    fclose(report);
}


// Main function called by main.c
void detect_threats_with_algorithm(
    const char *filename,
    SearchFunction search
) {
    if (search == NULL) {
        printf("Error: No search algorithm selected.\n");
        return;
    }

    // Pass 1: Count suspicious activity by IP
    count_suspicious_events(filename, search);

    // Pass 2: Generate report
    export_threat_report(filename, search);
}


// Backward-compatible function
void detect_threats(const char *filename) {
    detect_threats_with_algorithm(filename, naive_search);
}
