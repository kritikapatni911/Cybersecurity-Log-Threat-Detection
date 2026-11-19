
#include <stdio.h>

void read_log_file(const char *filename)
{
    FILE *file = fopen(filename, "r");

    if (file == NULL)
    {
        printf("Error: Could not open log file: %s\n", filename);
        return;
    }

    char line[1024];
    int line_number = 0;

    printf("\n----- SECURITY LOGS -----\n");

    while (fgets(line, sizeof(line), file) != NULL)
    {
        line_number++;
        printf("%d: %s", line_number, line);
    }

    fclose(file);

    printf("\nTotal log entries: %d\n", line_number);
}
