
#include <stdio.h>

// Threat detection function
void detect_threats_with_algorithm(
    const char *filename,
    int (*search)(const char *, const char *)
);

// Algorithm functions
int naive_search(const char *, const char *);
int rabin_karp_search(const char *, const char *);
int kmp_search(const char *, const char *);
int finite_automaton_search(const char *, const char *);

int main()
{
    int choice;

    const char *filename = "data/security_logs.txt";

    printf("\n====================================\n");
    printf(" CYBERSECURITY LOG THREAT DETECTION\n");
    printf("====================================\n");

    printf("\nSelect String Matching Algorithm:\n");
    printf("1. Naive Algorithm\n");
    printf("2. Rabin-Karp Algorithm\n");
    printf("3. KMP Algorithm\n");
    printf("4. Finite Automaton Algorithm\n");

    printf("\nEnter your choice (1-4): ");
    scanf("%d", &choice);

    switch (choice)
    {
        case 1:
            printf("\nUsing Naive Algorithm...\n");
            detect_threats_with_algorithm(filename, naive_search);
            break;

        case 2:
            printf("\nUsing Rabin-Karp Algorithm...\n");
            detect_threats_with_algorithm(filename, rabin_karp_search);
            break;

        case 3:
            printf("\nUsing KMP Algorithm...\n");
            detect_threats_with_algorithm(filename, kmp_search);
            break;

        case 4:
            printf("\nUsing Finite Automaton Algorithm...\n");
            detect_threats_with_algorithm(filename, finite_automaton_search);
            break;

        default:
            printf("\nInvalid choice! Select a number from 1 to 4.\n");
            return 1;
    }

    return 0;
}
