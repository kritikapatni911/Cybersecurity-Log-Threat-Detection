
# Cybersecurity Log Threat Detection System

## 1. Project Overview

The Cybersecurity Log Threat Detection System is a C-based terminal application designed to analyze system and network security logs, identify suspicious activities, detect repeated suspicious events, and compare the performance of different string matching algorithms.

## 2. Objectives

- Read and analyze security log records.
- Identify suspicious activities using pattern matching.
- Detect repeated suspicious activities from the same IP address.
- Classify detected events according to severity.
- Compare four string matching algorithms.
- Generate CSV reports.

## 3. Technologies Used

- Programming Language: C
- Compiler: GCC
- IDE: Visual Studio Code
- Data Storage: CSV files
- Version Control: Git and GitHub

## 4. Algorithms Implemented

1. Naive String Matching
2. Rabin-Karp Algorithm
3. Knuth-Morris-Pratt (KMP)
4. Finite Automaton Algorithm

## 5. Project Features

- Security log reading
- Suspicious activity detection
- Algorithm selection
- Event correlation by IP address
- Threat severity classification
- Algorithm performance benchmarking
- CSV report generation
- Interactive terminal menu

## 6. Threat Detection Rules

The system searches for these suspicious event patterns:

- LOGIN_FAILED
- UNAUTHORIZED_ACCESS
- MALWARE
- PORT_SCAN

Severity rules:

| Event | Severity |
|---|---|
| MALWARE | CRITICAL |
| UNAUTHORIZED_ACCESS | HIGH |
| PORT_SCAN | HIGH |
| LOGIN_FAILED (5 or more events from one IP) | HIGH |
| LOGIN_FAILED (fewer than 5 events from one IP) | MEDIUM |

These are predefined educational detection rules. A detected pattern indicates suspicious activity, not proof of an attack.

## 7. Project Structure

```text
Cybersecurity-Log-Threat-Detection/
|
|-- algorithms/
|   |-- naive.c
|   |-- rabin_karp.c
|   |-- kmp.c
|   |-- finite_automaton.c
|
|-- data/
|   |-- security_logs.txt
|
|-- output/
|
|-- src/
|   |-- main.c
|   |-- log_reader.c
|   |-- threat_detector.c
|   |-- event_correlation.c
|
|-- tests/
|   |-- test_naive.c
|   |-- test_rabin_karp.c
|   |-- test_kmp.c
|   |-- test_finite_automaton.c
|   |-- benchmark.c
|
|-- README.md
|-- .gitignore
```

## 8. Compilation

Run the following command from the project root:

```bash
gcc src/main.c src/log_reader.c src/threat_detector.c src/event_correlation.c algorithms/naive.c algorithms/rabin_karp.c algorithms/kmp.c algorithms/finite_automaton.c -o output/threat_detector.exe
```

## 9. Execution

On Windows PowerShell:

```powershell
.\output\threat_detector.exe
```

## 10. Benchmark Compilation

```bash
gcc tests/benchmark.c algorithms/naive.c algorithms/rabin_karp.c algorithms/kmp.c algorithms/finite_automaton.c -o output/benchmark.exe
```

Run:

```powershell
.\output\benchmark.exe
```

Benchmark results are exported to:

`output/benchmark_results.csv`

Threat detection results are exported to:

`output/threat_report.csv`

## 11. Complexity Analysis

Let n be the length of the input text and m be the length of the pattern.

| Algorithm | Time Complexity |
|---|---|
| Naive | O(n × m) |
| Rabin-Karp | Average O(n + m), worst O(n × m) |
| KMP | O(n + m) |
| Finite Automaton | O(n) search after preprocessing |

Preprocessing and memory costs depend on the implementation.

## 12. Limitations

- Uses predefined suspicious patterns.
- Uses simplified CSV log parsing.
- Focuses on IPv4 address correlation.
- Severity is based on fixed rules.
- Does not provide real-time network monitoring.

## 13. Future Enhancements

- Support additional log formats.
- Add more suspicious patterns.
- Support IPv6 addresses.
- Improve event correlation.
- Add more advanced detection rules.

## 14. Author

Cybersecurity Log Threat Detection Project
