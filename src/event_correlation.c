
#include <stdio.h>
#include <string.h>

#define MAX_IPS 100

// Store an IP address and its suspicious event count
struct IPCount
{
    char ip[16];
    int count;
};

// Check whether the event is suspicious
int is_suspicious_for_correlation(const char *event)
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

// Group suspicious events by IP address
void correlate_events(const char *filename)
{
    FILE *file = fopen(filename, "r");

    if (file == NULL)
    {
        printf("Error: Could not open log file.\n");
        return;
    }

    struct IPCount records[MAX_IPS] = {0};

    int unique_ips = 0;
    char line[1024];

    while (fgets(line, sizeof(line), file) != NULL)
    {
        // Extract CSV columns
        char *timestamp = strtok(line, ",\r\n");
        char *ip = strtok(NULL, ",\r\n");
        char *event = strtok(NULL, ",\r\n");

        if (timestamp == NULL || ip == NULL || event == NULL)
        {
            continue;
        }

        if (is_suspicious_for_correlation(event))
        {
            int found = 0;

            // Check whether this IP already exists
            for (int i = 0; i < unique_ips; i++)
            {
                if (strcmp(records[i].ip, ip) == 0)
                {
                    records[i].count++;
                    found = 1;
                    break;
                }
            }

            // Add a new IP if it has not been seen before
            if (!found && unique_ips < MAX_IPS)
            {
                strcpy(records[unique_ips].ip, ip);
                records[unique_ips].count = 1;
                unique_ips++;
            }
        }
    }

    fclose(file);

    printf("\n----- EVENT CORRELATION -----\n");

    int repeated_found = 0;

    for (int i = 0; i < unique_ips; i++)
    {
        if (records[i].count >= 2)
        {
            printf("\nIP Address: %s\n", records[i].ip);
            printf("Suspicious Events: %d\n", records[i].count);
            printf("Status: Repeated suspicious activity\n");

            repeated_found = 1;
        }
    }

    if (!repeated_found)
    {
        printf("No repeated suspicious activity found.\n");
    }
}
