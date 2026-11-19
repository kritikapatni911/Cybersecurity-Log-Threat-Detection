
#include <stdio.h>
#include <string.h>

// Naive String Matching Algorithm
int naive_search(const char *text, const char *pattern)
{
    int n = strlen(text);
    int m = strlen(pattern);

    // If pattern is empty, return 0
    if (m == 0)
    {
        return 0;
    }

    int count = 0;

    // Check every possible starting position
    for (int i = 0; i <= n - m; i++)
    {
        int j;

        // Compare pattern characters with text characters
        for (j = 0; j < m; j++)
        {
            if (text[i + j] != pattern[j])
            {
                break;
            }
        }

        // If all characters matched
        if (j == m)
        {
            count++;
        }
    }

    return count;
}
