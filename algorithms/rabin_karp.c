
#include <stdio.h>
#include <string.h>

#define BASE 256
#define PRIME 101

// Rabin-Karp String Matching Algorithm
int rabin_karp_search(const char *text, const char *pattern)
{
    int n = strlen(text);
    int m = strlen(pattern);

    // Handle an empty pattern
    if (m == 0)
    {
        return 0;
    }

    // Pattern cannot match if it is longer than the text
    if (m > n)
    {
        return 0;
    }

    long long pattern_hash = 0;
    long long text_hash = 0;
    long long h = 1;

    int count = 0;

    // Calculate BASE^(m-1) % PRIME
    for (int i = 0; i < m - 1; i++)
    {
        h = (h * BASE) % PRIME;
    }

    // Calculate initial hashes
    for (int i = 0; i < m; i++)
    {
        pattern_hash =
            (BASE * pattern_hash + (unsigned char)pattern[i]) % PRIME;

        text_hash =
            (BASE * text_hash + (unsigned char)text[i]) % PRIME;
    }

    // Slide the pattern over the text
    for (int i = 0; i <= n - m; i++)
    {
        // If hashes match, verify actual characters
        if (pattern_hash == text_hash)
        {
            int j;

            for (j = 0; j < m; j++)
            {
                if (text[i + j] != pattern[j])
                {
                    break;
                }
            }

            if (j == m)
            {
                count++;
            }
        }

        // Calculate hash for the next window
        if (i < n - m)
        {
            text_hash =
                (BASE * (text_hash -
                (unsigned char)text[i] * h) +
                (unsigned char)text[i + m]) % PRIME;

            // Ensure hash is non-negative
            if (text_hash < 0)
            {
                text_hash += PRIME;
            }
        }
    }

    return count;
}
