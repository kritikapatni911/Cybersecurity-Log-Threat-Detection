
#include <stdio.h>

int rabin_karp_search(const char *text, const char *pattern);

int main()
{
    const char *logs =
        "LOGIN_FAILED LOGIN_SUCCESS LOGIN_FAILED LOGIN_FAILED";

    const char *pattern = "LOGIN_FAILED";

    int result = rabin_karp_search(logs, pattern);

    printf("----- RABIN-KARP STRING MATCHING -----\n");
    printf("Log Data: %s\n", logs);
    printf("Pattern: %s\n", pattern);
    printf("Total Matches Found: %d\n", result);

    return 0;
}
