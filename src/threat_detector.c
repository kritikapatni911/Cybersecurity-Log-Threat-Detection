
#include <stdio.h>
#include <string.h>

// Check whether an event type is suspicious
int is_suspicious_event(const char *event)
{
    if (strcmp(event, "LOGIN_FAILED") == 0 ||
        strcmp(event, "UNAUTHORIZED_ACCESS") == 0 ||
        strcmp(event, "MALWARE") == 0 ||
        strcmp(event, "PORT_SCAN") == 0)
    {
        return 1;
    }

    return 0;
}

// Read the CSV file and detect suspicious events
void detect_threats(const char *filename)
{
    FILE *file = fopen(filename, "r");

    if (file == NULL)
    {
        printf("Error: Could not open log file.\n");
        return;
    }

    char line[1024];
    char original_line[1024];
    int suspicious_count = 0;

    printf("\n----- THREAT DETECTION -----\n");

    while (fgets(line, sizeof(line), file) != NULL)
    {
        strcpy(original_line, line);

        // Extract CSV columns
        char *timestamp = strtok(line, ",\r\n");
        char *ip = strtok(NULL, ",\r\n");
        char *event = strtok(NULL, ",\r\n");
        char *username = strtok(NULL, ",\r\n");

        // Ignore incomplete or empty lines
        if (timestamp == NULL || ip == NULL || event == NULL)
        {
            continue;
        }

        if (is_suspicious_event(event))
        {
            suspicious_count++;

            printf("\n[WARNING] Suspicious activity detected!\n");
            printf("IP Address: %s\n", ip);
            printf("Event: %s\n", event);

            if (username != NULL)
            {
                printf("Username: %s\n", username);
            }

            printf("Log: %s", original_line);
        }
    }

    printf("\nTotal suspicious entries: %d\n", suspicious_count);

    fclose(file);
}
