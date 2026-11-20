
#include <stdio.h>

#define MAX_LINE 1024

// Reads and displays all security log records
void read_logs(const char *filename)
{
    FILE *file;
    char line[MAX_LINE];
    int total_records = 0;

    file = fopen(filename, "r");

    if (file == NULL)
    {
        printf("\nError: Unable to open log file: %s\n", filename);
        return;
    }

    printf("\n====================================\n");
    printf("          SECURITY LOG READER\n");
    printf("====================================\n");

    while (fgets(line, sizeof(line), file) != NULL)
    {
        total_records++;
        printf("%d. %s", total_records, line);
    }

    printf("\n====================================\n");
    printf("Total log records: %d\n", total_records);
    printf("====================================\n");

    fclose(file);
}

// Counts the total number of records in the log file
int count_log_records(const char *filename)
{
    FILE *file;
    char line[MAX_LINE];
    int count = 0;

    file = fopen(filename, "r");

    if (file == NULL)
    {
        printf("\nError: Unable to open log file.\n");
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL)
    {
        count++;
    }

    fclose(file);

    return count;
}
