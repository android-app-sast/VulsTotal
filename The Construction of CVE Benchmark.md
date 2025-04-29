# The Construction of CVE Benchmark
After obtaining 1722 labels of Android-specific CVEs that fit the scope of our study, we endeavor to get their corresponding APK resources.
Firstly, concerning the initial 1,722 labels  we have conducted searches through mainstream app markets to match the corresponding APK versions. Despite these efforts, accessibility to many APKs remained elusive, with only 124 APKs ultimately obtained. However, AndroZoo certainly brought a breakthrough in our APK collection and significantly compensated for the unavailability of our APK resources because it continuously collects APKs from various sources. 
#### APK Collection.
We collected APKs from multiple sources. Initially, we searched CVE-specified apps from APKPure, APKMonk, Google Play, and other major app markets, downloaded their corresponding versions, and obtained APKs corresponding to 157 labels. For the remaining 1,565 labels without corresponding resources, we conducted further searches in Androzoo. Given its indexing by package names, we track down package name information for instances without finding APKs.  At this stage, some CVE descriptions directly disclose the package names,  while others necessitated consulting app markets for this detail. Unfortunately, due to missing package names, 70 instances were excluded. 
Utilizing obtained package names for exact matching in AndroZoo eliminated another 135 instances for its no hint in the database. Given the discrepancy between Androzoo's versionCode and the versionName described in CVEs, we employed AndroGuard to extract the actual version name of apps in Androzoo, pinpointing target APKs meeting version requirements. This process ruled out 201 instances that didn't meet the required version, leaving us with APKs for 1,159 instances.
#### APK Sampling
Among them, we found 1,118 instances involving 3 specified vulnerability types i.e., "Use Invalid Server Verification", "Use Invalid Hostname Verification'', and "Use Allow All Hostname Verification''.}. Due to resource and time constraints, we could not feasibly scan all instances. Focusing on the remaining 172 instances, we noted a maximum of 30 instances per single type.
Considering the 1,118 instances from Androzoo and the 25 instances from the app markets, a total of 1,143 instances, we opted to randomly select 30 instances from each of these three types to be included in the CVE benchmark for effectiveness evaluation. Subsequently, we added 10 more instances of each type until reaching a total of 60, continuously calculating Recall. We observed that involving four cases, the sample variance of Recall across tools on the CVE benchmark was under 0.1%. 
Based on this finding, we inferred that including all 1,143 instances versus including only 90 samples (30 per type) would have a negligible effect on the final results. 
Therefore, we chose 30 samples per type, resulting in the CVE benchmark including 250 CVEs encompassing 229 APKs, and 262 vulnerability instances that covered 34 vulnerability types named CVE-based benchmark.
#### Recall of four calculations
|  | QARK | AndroBugs | JAADAS | Marvin | SUPER | MobSF | SPECK | AUSERA | APKHunt | Trueseeing | DroidStatx |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Recall-30 | 68.1% | 92.9% | 86.7% | 74.3% | 52.3% | 84.8% | 91.8% | 89.7% | 94.9% | 86.1% | 92.6% |
| Recall-40 | 70.2% | 93.5% | 84.0% | 76.5% | 55.5% | 84.5% | 90.8% | 89.7% | 95.4% | 86.1% | 92.2% |
| Recall-50 | 68.2% | 93.0% | 87.9% | 78.7% | 55.0% | 82.4% | 88.5% | 89.0% | 95.9% | 86.1% | 90.3% |
| Recall-60 | 65.8% | 92.7% | 89.9% | 79.8% | 55.4% | 80.6% | 85.7% | 88.8% | 96.2% | 86.1% | 89.8% |
| Sample Variance | 0.03% | 0.00% | 0.06% | 0.06% | 0.02% | 0.04% | 0.07% | 0.00% | 0.00% | 0.00% | 0.02% |

 
