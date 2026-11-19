
#include <stdio.h>
#include <string.h>

#define NO_OF_CHARS 256

void compute_transition_function(
    const char *pattern,
    int m,
    int transition[][NO_OF_CHARS]
) {
    int state, x, k, j;
    
    for (state = 0; state <= m; state++) {
        for (x = 0; x < NO_OF_CHARS; x++) {

            k = (state + 1 < m) ? state + 1 : m;

            while (k > 0) {
                int match = 1;

                for (j = 0; j < k; j++) {
                    int index = state + 1 - k + j;

                    unsigned char current_char;

                    if (index < state) {
                        current_char =
                            (unsigned char)pattern[index];
                    } else {
                        current_char = (unsigned char)x;
                    }

                    if (current_char !=
                        (unsigned char)pattern[j]) {
                        match = 0;
                        break;
                    }
                }

                if (match) {
                    break;
                }

                k--;
            }

            transition[state][x] = k;
        }
    }
}

int finite_automaton_search(
    const char *text,
    const char *pattern
) {
    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0 || m > n) {
        return 0;
    }

    int transition[m + 1][NO_OF_CHARS];

    compute_transition_function(pattern, m, transition);

    int state = 0;
    int count = 0;

    for (int i = 0; i < n; i++) {

        state = transition[state]
            [(unsigned char)text[i]];

        if (state == m) {
            count++;
        }
    }

    return count;
}

