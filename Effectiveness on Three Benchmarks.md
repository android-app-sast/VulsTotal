# Effectiveness on Three Benchmarks
## CVE-based
| 
 | QARK | AndroBugs | JAADAS | Marvin | SUPER | MobSF | SPECK | AUSERA | APKHunt | Trueseeing | DroidStatx |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TP | 96 | 158 | 39 | 124 | 57 | 123 | 101 | 183 | 242 | 68 | 126 |
| FN | 45 | 12 | 6 | 43 | 52 | 22 | 9 | 21 | 13 | 11 | 10 |
| B_Recall of CVE-based | 68.09% | 92.94% | 86.67% | 74.25% | 52.29% | 84.83% | 91.82% | 89.71% | 94.90% | 86.08% | 92.65% |
| # Supported Vulnerability Cases | 141 | 170 | 45 | 167 | 109 | 145 | 110 | 204 | 255 | 79 | 136 |

## CVE-U
| 
 | QARK  | AndroBug | JAADAS | Marvine | SUPER | MobSF | SPECK | AUSERA | APKHunt | Trueseeing | DroidStatx |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TP | 14 | 31 | 9 | 20 | 14 | 34 | 27 | 47 | 58 | 14 | 25 |
| FN | 21 | 6 | 3 | 18 | 22 | 11 | 2 | 9 | 8 | 8 | 4 |
| B_Recall of CVE_U | 40.00% | 83.78% | 75.00% | 52.63% | 38.89% | 75.56% | 93.10% | 83.93% | 87.88% | 63.64% | 86.21% |
| # Supported Vulnerability Cases | 35 | 37 | 12 | 38 | 36 | 45 | 29 | 56 | 66 | 22 | 29 |

## MSTG&PIVAA
|  | MobSF | QARK | AndroBugs | APKHunt | SUPER | JAADAS | DroidStatx | Marvin | Trueseeing | AUSERA | SPECK |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TP | 15 | 1 | 14 | 23 | 12 | 2 | 11 | 5 | 10 | 18 | 11 |
| FN | 4 | 2 | 2 | 1 | 4 | 0 | 0 | 9 | 0 | 4 | 3 |
| Recall of MSTG&PIVAA | 78.9% | 33.3% | 87.5% | 95.8% | 75.0% | 100.0% | 100.0% | 35.7% | 100.0% | 81.8% | 78.6% |
| # Supported Vulnerability Cases | 19 | 3 | 16 | 24 | 16 | 2 | 11 | 14 | 10 | 22 | 14 |

## GHERA
| 
 | QARK  | AndroBugs | JAADAS | Marvin | SUPER | MobSF | SPECK | AUSERA | APKHunt | Trueseeing | DroidStatx |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| TP | 4 | 11 | 6 | 11 | 4 | 12 | 7 | 19 | 24 | 5 | 11 |
| FN | 9 | 4 | 3 | 7 | 8 | 6 | 6 | 2 | 4 | 2 | 2 |
| FP | 2 | 3 | 2 | 3 | 2 | 6 | 4 | 6 | 19 | 3 | 4 |
| TN | 11 | 12 | 7 | 15 | 10 | 12 | 9 | 15 | 9 | 4 | 9 |
| Precision | 66.7% | 78.6% | 75.0% | 78.6% | 66.7% | 66.7% | 63.6% | 76.0% | 55.8% | 62.5% | 73.3% |
| Recall | 30.8% | 73.3% | 66.7% | 61.1% | 33.3% | 66.7% | 53.8% | 90.5% | 85.7% | 71.4% | 84.6% |
| F1-score | 42.1% | 75.9% | 70.6% | 68.8% | 44.4% | 66.7% | 58.3% | 82.6% | 67.6% | 66.7% | 78.6% |
| FPR | 15.4% | 20.0% | 22.2% | 16.7% | 16.7% | 33.3% | 30.8% | 28.6% | 67.9% | 42.9% | 30.8% |
| # Supported Vulnerability Cases | 26 | 30 | 18 | 36 | 24 | 36 | 26 | 42 | 56 | 14 | 26 |

