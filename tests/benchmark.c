
#include <stdio.h>
#include <time.h>

/* Function declarations from our four algorithm files */

int naive_search(const char *text, const char *pattern);
int rabin_karp_search(const char *text, const char *pattern);
int kmp_search(const char *text, const char *pattern);
int finite_automaton_search(const char *text, const char *pattern);

#define ITERATIONS 10000

typedef int (*SearchFunction)(const char *, const char *);

void benchmark(
    const char *name,
    SearchFunction search,
    const char *text,
    const char *pattern
) {
    clock_t start, end;
    volatile int total_matches = 0;

    start = clock();

    for (int i = 0; i < ITERATIONS; i++) {
        total_matches += search(text, pattern);
    }

    end = clock();

    double elapsed_time =
        (double)(end - start) / CLOCKS_PER_SEC;

    printf("%-20s | Matches: %d | Time: %.6f seconds\n",
           name,
           total_matches / ITERATIONS,
           elapsed_time);
}

int main() {

    const char *text =
        "LOGIN_FAILED LOGIN_SUCCESS LOGIN_FAILED "
        "LOGIN_FAILED UNAUTHORIZED_ACCESS PORT_SCAN "
        "LOGIN_FAILED MALWARE LOGIN_SUCCESS";

    const char *pattern = "LOGIN_FAILED";

    printf("\n===== ALGORITHM PERFORMANCE COMPARISON =====\n");

    printf("Pattern: %s\n", pattern);
    printf("Iterations: %d\n\n", ITERATIONS);

    benchmark("Naive", naive_search, text, pattern);

    benchmark("Rabin-Karp", rabin_karp_search, text, pattern);

    benchmark("KMP", kmp_search, text, pattern);

    benchmark("Finite Automaton",
              finite_automaton_search, text, pattern);

    printf("\n BENCHMARK COMPLETED \n");

    return 0;
}

