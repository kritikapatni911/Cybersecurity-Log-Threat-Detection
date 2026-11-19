
#include <stdio.h>
#include <string.h>

// Build the LPS (Longest Prefix Suffix) array
void compute_lps(const char *pattern, int m, int lps[])
{
    int len = 0;
    int i = 1;

    lps[0] = 0;

    while (i < m)
    {
        if (pattern[i] == pattern[len])
        {
            len++;
            lps[i] = len;
            i++;
        }
        else
        {
            if (len != 0)
            {
                len = lps[len - 1];
            }
            else
            {
                lps[i] = 0;
                i++;
            }
        }
    }
}

// KMP String Matching Algorithm
int kmp_search(const char *text, const char *pattern)
{
    int n = strlen(text);
    int m = strlen(pattern);

    if (m == 0 || m > n)
    {
        return 0;
    }

    int lps[m];

    compute_lps(pattern, m, lps);

    int i = 0;
    int j = 0;
    int count = 0;

    while (i < n)
    {
        if (text[i] == pattern[j])
        {
            i++;
            j++;
        }

        if (j == m)
        {
            count++;
            j = lps[j - 1];
        }
        else if (i < n && text[i] != pattern[j])
        {
            if (j != 0)
            {
                j = lps[j - 1];
            }
            else
            {
                i++;
            }
        }
    }

    return count;
}
