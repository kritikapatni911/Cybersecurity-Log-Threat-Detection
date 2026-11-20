
#include <stdio.h>
#include <time.h>

// Algorithm declarations
int naive_search(const char *text, const char *pattern);
int rabin_karp_search(const char *text, const char *pattern);
int kmp_search(const char *text, const char *pattern);
int finite_automaton_search(const char *text, const char *pattern);

#define ITERATIONS 10000

typedef int (*SearchFunction)(const char *, const char *);

void benchmark_algorithm(
    FILE *report,
    const char *name,
    SearchFunction search,
    const char *text,
    const char *pattern
) {
    clock_t start, end;

    int matches = 0;

    start = clock();

    for (int i = 0; i < ITERATIONS; i++) {
        matches = search(text, pattern);
    }

    end = clock();

    double execution_time =
        (double)(end - start) / CLOCKS_PER_SEC;

    printf("\nAlgorithm: %s\n", name);
    printf("Matches found: %d\n", matches);
    printf("Execution time: %.6f seconds\n", execution_time);

    fprintf(
        report,
        "%s,%.6f,%d,%d\n",
        name,
        execution_time,
        matches,
        ITERATIONS
    );
}

int main() {

    const char *text =
        "LOGIN_FAILED LOGIN_SUCCESS LOGIN_FAILED "
        "LOGIN_FAILED LOGIN_FAILED";

    const char *pattern = "LOGIN_FAILED";

    FILE *report = fopen(
        "output/benchmark_results.csv",
        "w"
    );

    if (report == NULL) {
        printf("Error creating benchmark report.\n");
        return 1;
    }

    fprintf(
        report,
        "Algorithm,Execution_Time_Seconds,Matches_Found,Iterations\n"
    );

    printf("====================================\n");
    printf("   STRING MATCHING BENCHMARK\n");
    printf("====================================\n");

    printf("Iterations per algorithm: %d\n", ITERATIONS);

    benchmark_algorithm(
        report, "Naive",
        naive_search, text, pattern
    );

    benchmark_algorithm(
        report, "Rabin-Karp",
        rabin_karp_search, text, pattern
    );

    benchmark_algorithm(
        report, "KMP",
        kmp_search, text, pattern
    );

    benchmark_algorithm(
        report, "Finite Automaton",
        finite_automaton_search, text, pattern
    );

    fclose(report);

    printf("\n====================================\n");
    printf("Benchmark completed successfully!\n");
    printf("Report: output/benchmark_results.csv\n");
    printf("====================================\n");

    return 0;
}
