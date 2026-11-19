
#include <stdio.h>

void read_log_file(const char *filename);
void detect_threats(const char *filename);
void correlate_events(const char *filename);

int main()
{
    const char *filename = "data/security_logs.txt";

    printf("Cybersecurity Log Threat Detection Engine\n");
    printf("Program started successfully!\n");

    read_log_file(filename);

    detect_threats(filename);

    correlate_events(filename);

    return 0;
}
