
#include <stdio.h>

int finite_automaton_search(
    const char *text,
    const char *pattern
);

int main() {
    char text[] =
        "LOGIN_FAILED LOGIN_SUCCESS LOGIN_FAILED LOGIN_FAILED";

    char pattern[] = "LOGIN_FAILED";

    int result = finite_automaton_search(text, pattern);

    printf("----- FINITE AUTOMATON STRING MATCHING -----\n");
    printf("Log Data: %s\n", text);
    printf("Pattern: %s\n", pattern);
    printf("Total Matches Found: %d\n", result);

    return 0;
}
