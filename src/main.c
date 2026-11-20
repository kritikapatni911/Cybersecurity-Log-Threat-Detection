
#include <stdio.h>
#include <stdlib.h>

// Log file location
#define LOG_FILE "data/security_logs.txt"

// Function declarations from other C files
void read_logs(const char *filename);

void detect_threats_with_algorithm(
    const char *filename,
    int (*search)(const char *, const char *)
);

void correlate_events(const char *filename);

// String matching algorithm declarations
int naive_search(const char *text, const char *pattern);
int rabin_karp_search(const char *text, const char *pattern);
int kmp_search(const char *text, const char *pattern);
int finite_automaton_search(const char *text, const char *pattern);

// Function pointer for selecting an algorithm
typedef int (*SearchFunction)(const char *, const char *);

// Currently selected algorithm
SearchFunction selected_algorithm = naive_search;

int algorithm_choice = 1;

// Displays the main menu
void display_menu(void)
{
    printf("\n");
    printf("============================================\n");
    printf("       CYBERSECURITY LOG THREAT DETECTOR\n");
    printf("============================================\n");

    printf("1. Read Security Logs\n");
    printf("2. Detect Suspicious Activities\n");
    printf("3. Select String Matching Algorithm\n");
    printf("4. Analyze Suspicious IP Addresses\n");
    printf("5. View Threat Severity Report\n");
    printf("6. Compare Algorithm Performance\n");
    printf("7. Export Threat Report\n");
    printf("8. Exit\n");

    printf("============================================\n");
    printf("Enter your choice: ");
}

// Reads and displays the security logs
void read_security_logs(void)
{
    read_logs(LOG_FILE);
}

// Allows the user to select a string matching algorithm
void select_algorithm(void)
{
    int choice;

    printf("\n========== SELECT ALGORITHM ==========\n");

    printf("1. Naive String Matching\n");
    printf("2. Rabin-Karp Algorithm\n");
    printf("3. Knuth-Morris-Pratt (KMP)\n");
    printf("4. Finite Automaton Algorithm\n");

    printf("Enter your choice: ");

    if (scanf("%d", &choice) != 1)
    {
        printf("\nInvalid input.\n");

        while (getchar() != '\n');

        return;
    }

    switch (choice)
    {
        case 1:
            selected_algorithm = naive_search;
            algorithm_choice = 1;
            printf("\nNaive Algorithm selected successfully.\n");
            break;

        case 2:
            selected_algorithm = rabin_karp_search;
            algorithm_choice = 2;
            printf("\nRabin-Karp Algorithm selected successfully.\n");
            break;

        case 3:
            selected_algorithm = kmp_search;
            algorithm_choice = 3;
            printf("\nKMP Algorithm selected successfully.\n");
            break;

        case 4:
            selected_algorithm = finite_automaton_search;
            algorithm_choice = 4;
            printf("\nFinite Automaton Algorithm selected successfully.\n");
            break;

        default:
            printf("\nInvalid algorithm choice. Keeping previous selection.\n");
    }
}

// Detects suspicious activities using the selected algorithm
void detect_suspicious_activities(void)
{
    printf("\n========== THREAT DETECTION ==========\n");

    printf("Selected algorithm: ");

    switch (algorithm_choice)
    {
        case 1:
            printf("Naive String Matching\n");
            break;

        case 2:
            printf("Rabin-Karp Algorithm\n");
            break;

        case 3:
            printf("KMP Algorithm\n");
            break;

        case 4:
            printf("Finite Automaton Algorithm\n");
            break;
    }

    detect_threats_with_algorithm(
        LOG_FILE,
        selected_algorithm
    );
}

// Displays suspicious IP address activity
void analyze_suspicious_ips(void)
{
    printf("\n========== EVENT CORRELATION ==========\n");

    correlate_events(LOG_FILE);
}

// Displays the generated threat report
void view_threat_report(void)
{
    FILE *file;
    char line[1024];

    file = fopen("output/threat_report.csv", "r");

    if (file == NULL)
    {
        printf("\nThreat report not found.\n");
        printf("Run threat detection first to generate the report.\n");
        return;
    }

    printf("\n========== THREAT SEVERITY REPORT ==========\n\n");

    while (fgets(line, sizeof(line), file) != NULL)
    {
        printf("%s", line);
    }

    fclose(file);
}

// Generates or refreshes the CSV threat report
void export_report_menu(void)
{
    printf("\n========== EXPORT THREAT REPORT ==========\n");

    printf("Generating threat report using the selected algorithm...\n");

    detect_threats_with_algorithm(
        LOG_FILE,
        selected_algorithm
    );

    printf("\nCheck output/threat_report.csv for the exported report.\n");
}

// Runs the separate benchmark program
void compare_algorithm_performance(void)
{
    printf("\n========== ALGORITHM PERFORMANCE ==========\n");

    printf("Running benchmark program...\n\n");

    // Windows command for running the benchmark executable
    system("output\\benchmark.exe");
}

// Main function
int main(void)
{
    int choice;

    printf("\nWelcome to the Cybersecurity Log Threat Detection System!\n");

    while (1)
    {
        display_menu();

        if (scanf("%d", &choice) != 1)
        {
            printf("\nInvalid input. Please enter a number.\n");

            while (getchar() != '\n');

            continue;
        }

        switch (choice)
        {
            case 1:
                read_security_logs();
                break;

            case 2:
                detect_suspicious_activities();
                break;

            case 3:
                select_algorithm();
                break;

            case 4:
                analyze_suspicious_ips();
                break;

            case 5:
                view_threat_report();
                break;

            case 6:
                compare_algorithm_performance();
                break;

            case 7:
                export_report_menu();
                break;

            case 8:
                printf("\nThank you for using the system!\n");
                printf("Exiting...\n");
                return 0;

            default:
                printf("\nInvalid choice. Please select 1-8.\n");
        }
    }

    return 0;
}
