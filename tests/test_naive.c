
#include <stdio.h>

// Declaration of our function from naive.c
int naive_search(const char *text, const char *pattern);

int main()
{
    // Sample cybersecurity log data
    const char *logs =
        "LOGIN_FAILED LOGIN_SUCCESS LOGIN_FAILED LOGIN_FAILED";

    // Suspicious pattern we want to detect
    const char *pattern = "LOGIN_FAILED";

    // Call the Naive String Matching algorithm
    int result = naive_search(logs, pattern);

    printf("----- NAIVE STRING MATCHING -----\n");

    printf("Log Data: %s\n", logs);
    printf("Pattern: %s\n", pattern);

    printf("Total Matches Found: %d\n", result);

    return 0;
}
