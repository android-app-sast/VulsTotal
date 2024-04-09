# Platform Base (SAST Tools) Selection

To construct a unified platform and thoroughly evaluate the detection capabilities of Android SAST tools, we sought out a diverse set of SAST tools from both academic and industrial domains. To gather this information, we primarily searched tools from recent literature and two prominent websites including NIST and Gartner. Then we snowballed from them since they also recommend further lists. 

We further retrieved Android SAST tools from GitHub using keywords "Android vulnerability" and "Android static analysis" and sorting them by the number of stars. We aimed to collect tools with 10 or more stars, ensuring the inclusion of relatively popular and widely recognized tools.

After collating data from these diverse sources, we were able to identify 128 pertinent SAST tools in the domain of Android security, spanning both industry and academia. 

### Tools Sources:

We list the SAST tools from different sources as follows:

#### NIST [1] (6):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [OVERSECURED](https://oversecured.com/)                      | Enterprise vulnerability scanner for Android and iOS apps. Integrates into the development process to help app owners and developers secure each new version of the mobile app. |
| 2    | [CodeSonar](https://www.grammatech.com/products/source-code-analysis) | Data Races, Deadlocks, Thread Starvation, Buffer Overruns, Buffer Overflow, Leaks, Null Pointer Dereferences, Divide By Zero, Use After Free, Free of Non-Heap Variables, Uninitialized Variables, Returns of Pointers to Local, Returns of Pointers to Free, Free of Null Pointer, Unreachable Code, Try-locks that Cannot Succeed, Misuse of Memory Allocation, Misuse of Memory Copying, Misuse of Libraries, Command Injection, User-Defined Bug Classes, Runtime Error, Double Free, etc. |
| 3    | [DefenseCode ThunderScan](https://www.defensecode.com/thunderscan-sast/) | More than 60 vulnerability types, including SQL injection, XPATH injection, file disclosure, mail relay, page inclusion, dangerous configuration settings, code injection, dangerous file extensions, shell command execution, dangerous functions, cross site scripting, arbitrary server connection, weak encryption, HTTP response splitting, information leaks, LDAP injection. |
| 4    | [DerScanner](https://derscanner.com/)                        | DerScanner is a static app code analyzer capable of identifying vulnerabilities and backdoors (undocumented features). Its distinctive feature is the ability to analyze not only source code, but also executables (i.e. binaries). Aims to detect almost all known defects leading to vulnerabilities. |
| 5    | [Findsecbugs](https://find-sec-bugs.github.io/)              | Extends SpotBugs with more security detectors (Command Injection, XPath Injection, SQL/HQL Injection, Cryptography weakness and many more). |
| 6    | [Lucent Sky AVM](https://www.lucentsky.com/avm)              | Automatically finds and fixes application vulnerabilities, including cross-site scripting, SQL injection, path manipulation, etc., in source code. |

#### Gartner [2] (30):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [PITracker](https://github.com/Sp1keeeee/PItracker)          | PITracker: Detecting Android PendingIntent Vulnerabilities through Intent Flow Analysis |
| 2    | [App-ray](https://app-ray.co/)                               | App-Ray Static Analysis (SAST) and Dynamic Analysis (DAST) provides actionable results with 80+ types of security vulnerabilities, data management and privacy issues to identify |
| 3    | [Codified Security](https://codifiedsecurity.com/)           | Codified is the world's most popular testing platform for mobile application software which make it easier than ever for companies to detect and fix security vulnerabilities and ensure their applications are regulatory compliant. Discover and fix user mobile application security risks today with smart test technology platform. |
| 4    | [Quixxi](https://quixxisecurity.com/)                        | Quixxi is an intelligent and integrated end-to-end mobile app security solution. This powerful tool is for developers to protect and monitor any mobile app in minutes. |
| 5    | [ImmuniWeb MobileSuite](https://www.immuniweb.com/use-cases/#mobile-security-scanning) | Detect OWASP Mobile Top 10 weaknesses in all mobile apps with ImmuniWeb Discovery mobile security scanning. |
| 6    | [appknox](https://www.appknox.com/)                          | SAST, DAST, and API Scans Launch the holistic vulnerability assessment with a one-click static scan after uploading mobile app's binary. |
| 7    | [Fortify on Demand](https://www.microfocus.com/en-us/cyberres/application-security/fortify-on-demand) | Fortify on Demand is the application security provider to offer SAST, SCA, DAST, IAST, and MAST as a service. |
| 8    | [Synopsys](https://www.synopsys.com/software-integrity/application-security-testing-services/mobile-application-security-testing.html) | Synopsys Mobile Application Security Testing (MAST) enables users to implement client-side code, server-side code, and third-party library analysis quickly so users can systematically find and fix security vulnerabilities in mobile applications, without the need for source code. |
| 9    | [Checkmarx SAST](https://checkmarx.com/product/cxsast-source-code-scanning/) | Checkmarx Static Application Security Testing (SAST) provides fast and accurate incremental or full scans and gives users the flexibility, accuracy, integrations, and coverage to secure moblie applications |
| 10   | [eschecker](https://eshard.com/eschecker)                    | esChecker performs mobile application security testing at the binary level, where all the resources of the app are compiled and packaged, including 3rd parties SDK which source code review doesn’t take into consideration. |
| 11   | [nowsecure](https://www.nowsecure.com/)                      | NowSecure enables standards-based mobile app security testing and certification including OWASP MASVS, ADA MASA, ioXt, NIAP and more. |
| 12   | [Testhouse Managed Testing Services](https://www.testhouse.net/service-offerings/digital-assurance/mobility/) | Testhouse has a dedicated mobile testing practise to test applications across operating systems (iOS, Android and others) and their versions. Their testing practise will make sure application will work flawlessly across all mobile devices and platforms, delivering exceptional user experience. |
| 13   | [Data Theorem Mobile Secure](https://www.datatheorem.com/products/mobile-secure) | The Analyzer Engine will run a series of static and dynamic analyses for users' uploading applications, accounting for both backend APIs as well as third-party code. |
| 14   | [pradeo](https://www.pradeo.com/en-US/mobile-application-security-testing) | Pradeo’s mobile threat detection technology leans on a patented Artificial Intelligence process that precisely reveals and qualifies behaviors and vulnerabilities. Along the years, the Pradeo Security mobile application security testing platform has identified billions of behaviors and vulnerabilities. |
| 15   | [Appthority MTP](https://help-mtp.appthority.com/WelcomeToMTP.html) | MTP Manager has a Dashboard that gives quick summaries of mobile threat detection status for the Organization. |
| 16   | [derscanner](https://derscanner.com/)                        | DerScanner is a convenient and easy-to-use officially CWE-Compatible solution that combines the capabilities of static (SAST), dynamic (DAST) and software composition analysis (SCA) in a single interface. |
| 17   | [Entersoft Mobile Application Security](https://entersoftsecurity.com/mobile-app-security) | Entersoft's SAST methodology is a powerful solution for identifying potential security vulnerabilities within applications' source code. Our SAST approach provides a comprehensive analysis of your codebase, examining it line by line, to identify and remediate any potential weaknesses that could be exploited by attackers. |
| 18   | [Kryptowire](https://www.quokka.io/solutions/mobile-app-security-testing) | Kryptowire(Quokka)MAST’s unique combination of advanced analysis engines digs deeper and tests more thoroughly than any other MAST solution on the market. Our combination of using SAST, DAST and IAST, plus extensive proprietary engines that go beyond these common methodologies enabling the discovery of more CVEs than any other application security company. |
| 19   | [Varutra](https://www.varutra.com/cyber-security-services/mobile-applications-security/) | Varutra provide Mobile Application Security Services across different platforms such as - Android, i0S of type Native, Hybrid, Web as well as Mobile Device Management apps. |
| 20   | [Zimperium zScan](https://www.zimperium.com/zscan/)          | zScan leverages machine learning and rulesets for uncovering latent issues and support tailor scans to focus on specific areas of concern |
| 21   | [AppSonar](https://www.appsonar.com/)                        | AppSonar is a security testing software that helps improve the security and quality of your applicationThe test rules are based on industry standards including but not limited to OWASP Top 10, CWE/SANS-25 and NIST. |
| 22   | [Appsweep](https://appsweep.guardsquare.com/)                | Quickly find & solve security issues in your mobile app’s code and dependencies, based on security standards (e.g. OWASP MASVS ). Actionable recommendations enable quick resolution, keeping launches on time and on budget. And it is free. |
| 23   | [NowSecure Platform](https://www.gartner.com/reviews/market/mobile-application-security-testing/vendor/nowsecure/product/nowsecure-platform) | Great Mobile security product for quick scanning             |
| 24   | [APPScan](https://www.gartner.com/reviews/market/mobile-application-security-testing/vendor/hcltech-hcl-software/product/hcl-appscan) | Appscan is an amazing and powerful tool that can scan web applications automatically and it's great for its ability to prioritize vulnerabilities based on their severity. |
| 25   | [Syhunt](https://www.gartner.com/reviews/market/mobile-application-security-testing/vendor/syhunt/product/syhunt-hybrid) | Syhunt Hybrid is highly trusted web application security scanner which provides great accuracy in detecting vulnerabilities and all around security. Highly recommended. |
| 26   | [Continuous Hacking](https://fluidattacks.com/services/continuous-hacking/) | Find, exploit and report user's software's vulnerabilities throughout the entire software development lifecycle without delaying deployments. |
| 27   | [Ostorlab](https://www.ostorlab.co/)                         | Mobile Security Testing Automation for Android and iOS       |
| 28   | [Flexib+](https://www.3i-infotech.com/flexib/)               | FlexibTM+ enables organizations to integrate testing into their DevOps process, ensuring safety and performance in software development. It allows for the creation of automated build and test pipelines, acceleration of functional testing, application monitoring, and early integration of security in the DevOps cycle. This helps organizations increase agility, speed, and reduce costs while addressing critical requirements in software development. |
| 29   | [IBM Application Security on Cloud](https://www.ibm.com/docs/ja/tsafm/4.1.1?topic=reference-ibmapplication) | Application vulnerability scanning                           |
| 30   | [ScienceSoft Mobile Application Security Testing Services](https://www.scnsoft.com/software-testing/services/mobile) | Experienced with mobile testing specifics, ScienceSoft’s high-performing testing engineers validate all aspects of your mobile app within optimal testing time and budget. |

#### Keyword "Android  static  analysis" in GitHub [3] (18):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis. |
| 2    | [gradle-static-analysis-plugin](https://github.com/novoda/gradle-static-analysis-plugin) | Easy setup of static analysis tools for Android and Java projects. |
| 3    | [Adhrit](https://github.com/abhi-r3v0/Adhrit)                | Adhrit is an open source Android APK reversing and analysis suite. The tool is an effort to find an efficient solution to all the needs of mobile security testing and automation. Adhrit has been built with a focus on flexibility and mudularization. Adhrit currently uses the Ghera benchmarks to identify vulnerability patterns in Android applications. |
| 4    | [APKHunt](https://github.com/Cyber-Buddy/APKHunt)            | APKHunt is a comprehensive static code analysis tool for Android apps that is based on the OWASP MASVS framework. Although APKHunt is intended primarily for mobile app developers and security testers, it can be used by anyone to identify and address potential security vulnerabilities in their code. |
| 5    | [mariana-trench](https://github.com/facebook/mariana-trench) | A security focused static analysis tool for Android and Java applications. |
| 6    | [Appshark](https://github.com/bytedance/appshark)            | Appshark is a static taint analysis platform to scan vulnerabilities in an Android app. |
| 7    | [insider](https://github.com/insidersec/insider)             | Insider is focused on covering the OWASP Top 10, to make source code analysis to find vulnerabilities right in the source code, focused on a agile and easy to implement software inside your DevOps pipeline. |
| 8    | [aparoid](https://github.com/stefan2200/aparoid)             | Aparoid is a framework designed for Android application analysis. It offers an automated set of tools to discover vulnerabilities and other risks in mobile applications. It is built using the Flask framework and offers a web GUI to upload APK files and explore the contents / results. |
| 9    | [static-analysis-plugin](https://github.com/GradleUp/static-analysis-plugin) | Easy setup of static analysis tools for Android and Java projects. |
| 10   | [Marvin-SF](https://github.com/programa-stic/Marvin-static-Analyzer) | Marvin static analyzer is an Android application vulnerability scanner. The framework uses androguard and Static Android Analysis Framework |
| 11   | [droidstatx](https://github.com/devoteam-cybertrust/droidstatx) | Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis. |
| 12   | [Android Check](https://github.com/noveogroup/android-check) | Static code analysis plugin for Android project.             |
| 13   | [androlic](https://github.com/pangeneral/Androlic)           | Developers can take Androlic as a command line tool or develop self-defined static analysis tools by extending APIs of Androlic. Whatever we want to do, we need to get the following file: |
| 14   | [a5](https://github.com/tvidas/a5)                           | A distributed, dynamic and static analysis security sandbox for Android, all open source. |
| 15   | [HybridFlow](https://github.com/yuanchun-li/HybridFlow)      | Static taint analysis for Android Hybrid Apps (Java + HTML). |
| 16   | [HornDroid](https://github.com/ylya/horndroid)               | A Static Analysis Tool For Android Apps                      |
| 17   | [AndroShield](https://github.com/AmrAshraf/AndroShield)      | Automated Vulnerability Detection of Android Applications Web Application |
| 18   | [Static Code Analysis](https://github.com/Monits/static-code-analysis-plugin) | A plugin to simplify Static Code Analysis on Gradle. Not restricted to, but specially useful, in Android projects, by making sure all analysis can access the SDK classes. |

#### Keyword "Android vulnerability" in GitHub[4] (19):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [QARK](https://github.com/linkedin/qark)                     | Tool to look for several security related Android application vulnerabilities |
| 2    | [Appshark](https://github.com/bytedance/appshark)            | Appshark is a static taint analysis platform to scan vulnerabilities in an Android app. |
| 3    | [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework) | A vulnerability scanner for Android apps                     |
| 4    | [Android SSL Vulnerability Detection Tools](https://github.com/grahamedgecombe/android-ssl) | A set of tools for detecting if Android applications are vulnerable to common SSL certificate validation security vulnerabilities which allow man-in-the-middle attackers to intercept and modify encrypted network traffic. |
| 5    | [redos-detector](https://github.com/olivo/redos-detector)    | A tool for detecting regular expression denial-of-service vulnerabilities in Android apps. |
| 6    | [QUARK-engine](https://github.com/quark-engine/quark-engine) | Dig Vulnerabilities in the BlackBox                          |
| 7    | [Hopper](https://github.com/cuplv/hopper)                    | Hopper is a goal-directed static analysis tool for languages that run on the JVM. It is a much-improved and more feature-ful version of Thresher written in Scala rather than Java. |
| 8    | [BackDroid](https://github.com/VPRLab/BackDroid)             | BackDroid: Targeted and Efficient Inter-procedural Analysis of Modern Android Apps |
| 9    | [APKHunt](https://github.com/Cyber-Buddy/APKHunt)            | APKHunt is a comprehensive static code analysis tool for Android apps that is based on the OWASP MASVS framework. Although APKHunt is intended primarily for mobile app developers and security testers, it can be used by anyone to identify and address potential security vulnerabilities in their code. |
| 10   | [insider](https://github.com/insidersec/insider)             | Insider is focused on covering the OWASP Top 10, to make source code analysis to find vulnerabilities right in the source code, focused on a agile and easy to implement software inside your DevOps pipeline. |
| 11   | [droid-hunter](https://github.com/hahwul/droid-hunter/tree/master/sample) | Android application vulnerability analysis and Android pentest tool |
| 12   | [Marvin-SF](https://github.com/programa-stic/Marvin-static-Analyzer) | Marvin static analyzer is an Android application vulnerability scanner. The framework uses androguard and Static Android Analysis Framework |
| 13   | [apekit](https://github.com/ksparakis/apekit)                | Mass Android app vulnerability analysis toolkit              |
| 14   | [droidstatx](https://github.com/devoteam-cybertrust/droidstatx) | Python tool that generates an Xmind map with all the information gathered and any evidence of possible vulnerabilities identified via static analysis. |
| 15   | [AndroShield](https://github.com/AmrAshraf/AndroShield)      | Automated Vulnerability Detection of Android Applications Web Application |
| 16   | [AUSERA](https://github.com/tjusenchen/AUSERA)               | AUSERA is an automated tool for detecting security vulnerabilties in Android apps. |
| 17   | [SMV-Hunter](https://github.com/utds3lab/SMVHunter)          | Set of tools for performing large-scale automated detection of SSL/TLS man-in-the-middle vulnerabilities in Android apps. |
| 18   | [SPECK](https://github.com/SPRITZ-Research-Group/SPECK)      | This repo contains the code for our paper "SPECK: From Google Textual Guidelines to Automatic Detection of Android Apps Vulnerabilities". It includes both the code of our tool, SPECK, as well as the code of IVA, an Intentionally Vulnerable App used in our evaluation. |
| 19   | [trueseeing](https://github.com/alterakey/trueseeing)        | trueseeing is a fast, accurate and resillient vulnerabilities scanner for Android apps. It operates on Android Packaging File (APK) and outputs a comprehensive report in HTML, JSON or a CI-friendly format. It doesn't matter if the APK is obfuscated or not. |

#### Ranganath [5] (25):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [Amandroid](http://pag.arguslab.org/argus-saf)               | A static analysis framework with built-in checkers to look for vulnerabilities in Android apps |
| 2    | [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework) | A vulnerability scanner for Android apps                     |
| 3    | [AppAudit](http://appaudit.io/#)                             | Detects data leaks                                           |
| 4    | [AppCritique](https://appcritique.boozallen.com/upload)      | An online tool that detects several vulnerabilities in Android apps |
| 5    | [AppRay](http://app-ray.co/)                                 | A tool to identify vulenrabilities automatically             |
| 6    | [Covert](https://www.ics.uci.edu/~seal/projects/covert/)     | A tool for compositional verification of Android inter-application vulnerabilities |
| 7    | [DIALDroid](https://github.com/dialdroid-android/DIALDroid)  | A tool to detect inter-app vulnerabilities                   |
| 8    | [DIDFAIL](https://www.cs.cmu.edu/~wklieber/didfail/)         | A static taint analyzer for Android apps                     |
| 9    | [DeepDroid](https://github.com/fitzlee/DeepDroid)            | No information provided about the tool except source code    |
| 10   | [DevKnox](https://devknox.io/)                               | An Android Studio Plugin that detects vulnerabilities in Android apps |
| 11   | [DroidLegacy](https://bitbucket.org/srl/droidlegacy/src/master/) | No information provided about the tool except source code    |
| 12   | [FLowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/) | A static taint analysis tool for Android apps                |
| 13   | [FixDroid](https://plugins.jetbrains.com/plugin/9497-fixdroid) | An Android Studio plugin that provides warning to developers about potential vulnerabilities |
| 14   | [HornDroid](https://github.com/ylya/horndroid)               | A static analysis tool that detects sensitive information leak in Android apps |
| 15   | [IccTA](https://github.com/lilicoding/soot-infoflow-android-iccta) | A tool for inter-component Taint analysis in Android         |
| 16   | [JAADAS](https://github.com/flankerhqd/JAADAS)               | A static analysis that detects vulnerabilities in Android apps |
| 17   | [Mallodroid](https://github.com/sfahl/mallodroid)            | A tool to detect broken SSL certificate valiadation in Android apps |
| 18   | [Marvin-SF](https://github.com/programa-stic/Marvin-static-Analyzer) | An Android app vulnerability scanner                         |
| 19   | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | An automated pen-testing framework capable of performing static analysis and dynamic analysis to uncover vulnerabilities in Android apps |
| 20   | [Qark](https://github.com/linkedin/qark/)                    | A tool to look for several security related Android application vulnerabilities |
| 21   | [SMV_Hunter](https://github.com/utds3lab/SMVHunter)          | A tool-set for performing large-scale automated detection of SSL/TLS man-in-the-middle vulnerabilities in Android apps |
| 22   | [ScanDroid](https://www.cs.umd.edu/~avik/papers/scandroidascaa.pdf) | A tool that scans Android apps for inconcsistent data flows  |
| 23   | [StaDyna](https://github.com/zyrikby/StaDynA)                | A tool to address the problem dynamic code updates in Android apps |
| 24   | [TaintDroid](http://www.appanalysis.org/index.html)          | A realtime monitoring tool that analyses how private information is obtained and released by Android apps |
| 25   | [WeChecker](https://github.com/TRUEJASONFANS/Wechecker)      | A tool to check for Privilege Escalation                     |

#### Reaves et al. [6] (18):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [FLowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/) | FlowDroid statically computes data flows in Android apps and Java programs.But assumes that the entire contents remain tainted, even if an untainted value overwrites the single array element. |
| 2    | [Amandroid](http://pag.arguslab.org/argus-saf)               | A static analysis framework with built-in checkers to look for vulnerabilities in Android apps |
| 3    | [Mallodroid](https://github.com/sfahl/mallodroid)            | A tool to detect broken SSL certificate valiadation in Android apps |
| 4    | Epicc                                                        |                                                              |
| 5    | CryptoLint                                                   |                                                              |
| 6    | CLAPP                                                        |                                                              |
| 7    | CHEX                                                         |                                                              |
| 8    | Stowaway                                                     |                                                              |
| 9    | PScout                                                       |                                                              |
| 10   | DIDFail                                                      |                                                              |
| 11   | COPES                                                        |                                                              |
| 12   | SEFA                                                         |                                                              |
| 13   | AAPL                                                         |                                                              |
| 14   | Intent input Validation Vulnerability                        |                                                              |
| 15   | DroidJust                                                    |                                                              |
| 16   | SCANDAL                                                      |                                                              |
| 17   | WeChecker                                                    |                                                              |
| 18   | Comdroid                                                     |                                                              |

#### Senanayake et al. [7] (13):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [FlowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/) | FlowDroid statically computes data flows in Android apps and Java programs.But assumes that the entire contents remain tainted, even if an untainted value overwrites the single array element. |
| 2    | [Covert](https://www.ics.uci.edu/~seal/projects/covert/)     | Ability to perform compositional analysis of inter-app vulnerabilities.Unable to identify native code-related vulnerabilities and Permission leakages. |
| 3    | [DIALDroid](https://github.com/dialdroid-android/DIALDroid)  | Ability to identify privilege escalations and inter-app collusion.Unable to resolve relective calls if their arguments do not contain string constants and may fail to compute some ICC links due to ignoring over-approximated regular expressions. |
| 4    | [HornDroid](https://github.com/ylya/horndroid)               | Ability to perform static analysis of information lows, and ability to soundly abstract the semantic of Android apps to compose security properties. |
| 5    | [Mallodroid](https://github.com/sfahl/mallodroid)            | Ability to identify broken SSL certiication validation using Androgurd framework |
| 6    | [JAADAS](https://github.com/flankerhqd/JAADAS)               | A static analysis that detects vulnerabilities in Android apps |
| 7    | [DevKnox](https://devknox.io/)                               |                                                              |
| 8    | [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework) | A vulnerability scanner for Android apps                     |
| 9    | [Marvin-SF](https://github.com/programa-stic/Marvin-static-Analyzer) | An Android app vulnerability scanner                         |
| 10   | [Qark](https://github.com/linkedin/qark/)                    | Tool to look for several security related Android application vulnerabilities |
| 11   | [FixDroid](https://plugins.jetbrains.com/plugin/9497-fixdroid) | An Android Studio plugin that provides warning to developers about potential vulnerabilities |
| 12   | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | An automated pen-testing framework capable of performing static analysis and dynamic analysis to uncover vulnerabilities in Android apps |
| 13   | [Amandroid](http://pag.arguslab.org/argus-saf)               | A static analysis framework with built-in checkers to look for vulnerabilities in Android apps |

#### Chen et al. [8] (5):

|      | Tool Name                                                    | Notes                                                        |
| ---- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | [AUSERA](https://github.com/tjusenchen/AUSERA)               | AUSERA is an automated security risk assessment tool for Android application vulnerability detection. It uses static program analysis, such as data flow and control flow analysis, sensitive data labeling, function identification, etc., to automatically detect vulnerabilities in Android applications |
| 2    | [SUPER](https://github.com/SUPERAndroidAnalyzer/super)       | SUPER is a command line application which look for security related vulnerabilities for Android applications. RUST is used as its programming language, and therefore the tool can be extended. In addition, because it is a modular writing rules, so the user can customize the rules. |
| 3    | [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework) | A vulnerability scanner for Android apps                     |
| 4    | [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | An automated pen-testing framework capable of performing static analysis and dynamic analysis to uncover vulnerabilities in Android apps |
| 5    | [Qark](https://github.com/linkedin/qark/)                    | Tool to look for several security related Android application vulnerabilities |

We obtained a total of 128 SAST tools through the above sources.

After collating data and filtering out duplicate entries, we identified 97 pertinent SAST tools in the Android security domain, spanning both industry and academia. To facilitate the selection and comparison of Android SAST tools for our study, we designed five selection criteria as follows.

### Tools Selection:

To facilitate the selection and comparison of Android SAST tools for our study, we then designed 6 selection criterias as follows:

- Free of charge and transparent; 
- Github Stars;
- Available documentation and usability;
- Tools compatible with APK files;
- Command-line interface;
- Generalized vulnerability detection; 

#### Free of charge and transparent

The Android SAST tools must be free of charge. While commercial tools are indeed prevalent in the industry, they often entail substantial costs, which would be prohibitive for our large-scale experiment. Additionally, since we attempted to explore the internal implementation of the tool candidates, we filtered out 46 tools that are not transparent or free, such as Quixxi, ImmuniWeb, and Checkmarx SAST.

We show the performance of filtered tools 46 tools under this criteria.

| Tool Name                                                    | Free of charge and transparent |
| ------------------------------------------------------------ | ------------------------------ |
| [AppCritique](https://appcritique.boozallen.com/upload)      | ×                              |
| [AppRay](http://app-ray.co/)                                 | ×                              |
| [StaDyna](https://github.com/zyrikby/StaDynA)                | ×                              |
| CryptoLint                                                   | ×                              |
| CLAPP                                                        | ×                              |
| CHEX                                                         | ×                              |
| Stowaway                                                     | ×                              |
| COPES                                                        | ×                              |
| SEFA                                                         | ×                              |
| AAPL                                                         | ×                              |
| Intent input Validation Vulnerability Detection              | ×                              |
| DroidJust                                                    | ×                              |
| SCANDAL                                                      | ×                              |
| Comdroid                                                     | ×                              |
| [androlic](https://github.com/pangeneral/Androlic)           | ×                              |
| [Codified Security](https://codifiedsecurity.com/)           | ×                              |
| [Quixxi](https://quixxisecurity.com/)                        | ×                              |
| [ImmuniWeb MobileSuite](https://www.immuniweb.com/use-cases/#mobile-security-scanning) | ×                              |
| [appknox](https://www.appknox.com/)                          | ×                              |
| [Fortify on Demand](https://www.microfocus.com/en-us/cyberres/application-security/fortify-on-demand) | ×                              |
| [Synopsys](https://www.synopsys.com/software-integrity/application-security-testing-services/mobile-application-security-testing.html) | ×                              |
| [Checkmarx SAST](https://checkmarx.com/product/cxsast-source-code-scanning/) | ×                              |
| [eschecker](https://eshard.com/eschecker)                    | ×                              |
| [nowsecure](https://www.nowsecure.com/)                      | ×                              |
| [Testhouse Managed Testing Services](https://www.testhouse.net/service-offerings/digital-assurance/mobility/) | ×                              |
| [Data Theorem Mobile Secure](https://www.datatheorem.com/products/mobile-secure) | ×                              |
| [pradeo](https://www.pradeo.com/en-US/mobile-application-security-testing) | ×                              |
| [Appthority MTP](https://help-mtp.appthority.com/WelcomeToMTP.html) | ×                              |
| [Entersoft Mobile Application Security](https://entersoftsecurity.com/mobile-app-security) | ×                              |
| [Kryptowire](https://www.quokka.io/solutions/mobile-app-security-testing) | ×                              |
| [Varutra](https://www.varutra.com/cyber-security-services/mobile-applications-security/) | ×                              |
| [Zimperium zScan](https://www.zimperium.com/zscan/)          | ×                              |
| [AppSonar](https://www.appsonar.com/)                        | ×                              |
| [Appsweep](https://appsweep.guardsquare.com/)                | ×                              |
| [APPScan](https://www.gartner.com/reviews/market/mobile-application-security-testing/vendor/hcltech-hcl-software/product/hcl-appscan) | ×                              |
| [Syhunt](https://www.syhunt.com/en/?n=Products.SyhuntHybrid) | ×                              |
| [Continuous Hacking](https://fluidattacks.com/services/continuous-hacking/) | ×                              |
| [Ostorlab](https://www.ostorlab.co/)                         | ×                              |
| [Flexib+](https://www.3i-infotech.com/flexib/)               | ×                              |
| [IBM Application Security on Cloud](https://www.ibm.com/cloud-security) | ×                              |
| [ScienceSoft Mobile Application Security Testing Services](https://www.scnsoft.com/software-testing/services/mobile) | ×                              |
| [OVERSECURED](https://oversecured.com/)                      | ×                              |
| [CodeSonar](https://www.grammatech.com/products/source-code-analysis) | ×                              |
| [DefenseCode ThunderScan](https://www.defensecode.com/thunderscan-sast/) | ×                              |
| [DerScanner](https://derscanner.com/)                        | ×                              |
| [Lucent Sky AVM](https://www.lucentsky.com/avm)              | ×                              |

#### Github Stars

We further use the second criteria filtering out.

We tailed the number of stars for all tools available on GitHub and filtered out the tools with fewer than 10 stars like WeChecker to focus on more widely recognized and potentially more established tools. We excluded one tool eventually as follows.

| Tool Name                                               | Free of charge and transparent | Github Stars |
| ------------------------------------------------------- | ------------------------------ | ------------ |
| [WeChecker](https://github.com/TRUEJASONFANS/Wechecker) | √                              | 0            |

#### Available documentation and usability

For the remaining 50 tools, we use the thrid criteria filtering out.

The Android SAST tools must be operational and accompanied by available documentation, eliminating the human bias introduced by the efforts required to discover how to build and use them. Thus, we filtered out 7 tools that lacked proper documentation or not working, such as DroidLegacy (No documentation about usage) as follows. 

| Tool Name                                                    | Free of charge and transparent | Github Stars | Available documentation and usability |
| ------------------------------------------------------------ | ------------------------------ | ------------ | ------------------------------------- |
| [AppAudit](http://appaudit.io/#)                             | √                              |              | ×                                     |
| [DIDFAIL](https://www.cs.cmu.edu/~wklieber/didfail/)         | √                              |              | ×                                     |
| [DeepDroid](https://github.com/fitzlee/DeepDroid)            | √                              |              | ×                                     |
| [DroidLegacy](https://bitbucket.org/srl/droidlegacy/src/master/) | √                              |              | ×                                     |
| [Adhrit](https://github.com/abhi-r3v0/Adhrit)                | √                              | 524          | ×                                     |
| [a5](https://github.com/tvidas/a5)                           | √                              | 12           | ×                                     |
| [QUARK-engine](https://github.com/quark-engine/quark-engine) | √                              | 1.1k         | ×                                     |

#### Tools compatible with APK files

For the remaining 43 tools, as the APK files provide a comprehensive representation of an Android application, aiding in more realistic vulnerability discovery and analysis, we filtered out 10 tools that do not support APK files as input, such as Android Check and FindSecurityBugs.

| Tool Name                                                    | Free of charge and transparent | Github Stars | Available documentation and usability | Tools compatible with APK files |
| ------------------------------------------------------------ | ------------------------------ | ------------ | ------------------------------------- | ------------------------------- |
| [DevKnox](https://devknox.io/)                               | √                              |              | √                                     | ×                               |
| [FixDroid](https://plugins.jetbrains.com/plugin/9497-fixdroid) | √                              | 941          | √                                     | ×                               |
| [apekit](https://github.com/ksparakis/apekit)                | √                              | 13           | √                                     | ×                               |
| [gradle-static-analysis-plugin](https://github.com/novoda/gradle-static-analysis-plugin) | √                              | 407          | √                                     | ×                               |
| [insider](https://github.com/insidersec/insider)             | √                              | 464          | √                                     | ×                               |
| [static-analysis-plugin](https://github.com/GradleUp/static-analysis-plugin) | √                              | 64           | √                                     | ×                               |
| [Android Check](https://github.com/noveogroup/android-check) | √                              | 267          | √                                     | ×                               |
| [Static Code Analysis](https://github.com/Monits/static-code-analysis-plugin) | √                              | 38           | √                                     | ×                               |
| [Hopper](https://github.com/cuplv/hopper)                    | √                              | 55           | √                                     | ×                               |
| [Findsecbugs](https://find-sec-bugs.github.io/)              | √                              |              | √                                     | ×                               |

#### Command-line interface

For the remaining 33 tools, since we aim to perform automated large-scale scanning, tools solely offering a web user interface without any API capabilities are unsuitable. Therefore, We filtered out 2 tools.
For instance, Aparoid is excluded due to its lack of API integration, unlike tools such as MobSF that provide.

| Tool Name                                               | Free of charge and transparent | Github Stars | Available documentation and usability | Tools compatible with APK files | Command-line interface |
| ------------------------------------------------------- | ------------------------------ | ------------ | ------------------------------------- | ------------------------------- | ---------------------- |
| [aparoid](https://github.com/stefan2200/aparoid)        | √                              | 70           | √                                     | √                               | ×                      |
| [AndroShield](https://github.com/AmrAshraf/AndroShield) | √                              | 17           | √                                     | √                               | ×                      |

#### Generalized vulnerability detection

For the remaining 31 tools, since we aim to understand the extent of coverage for various types of vulnerabilities by current Android SAST tools. Thus, it is crucial that the selected tools can identify a wide range of Android vulnerabilities. Therefore, we excluded 20 tools that are designed to detect specific vulnerability types, such as SMV-Hunter (detecting SSL/TLS MITM vulnerabilities), and FlowDroid (Taint analysis). 

| Tool Name                                                    | Free of charge and transparent | Github Stars | Available documentation and usability | Tools compatible with APK files | Command-line interface | Generalized vulnerability detection |
| ------------------------------------------------------------ | ------------------------------ | ------------ | ------------------------------------- | ------------------------------- | ---------------------- | ----------------------------------- |
| [Amandroid](http://pag.arguslab.org/argus-saf)               | √                              |              | √                                     | √                               | √                      | ×                                   |
| [Covert](https://www.ics.uci.edu/~seal/projects/covert/)     | √                              |              | √                                     | √                               | √                      | ×                                   |
| [DIALDroid](https://github.com/dialdroid-android/DIALDroid)  | √                              | 17           | √                                     | √                               | √                      | ×                                   |
| [FLowDroid](https://blogs.uni-paderborn.de/sse/tools/flowdroid/) | √                              |              | √                                     | √                               | √                      | ×                                   |
| [HornDroid](https://github.com/ylya/horndroid)               | √                              | 17           | √                                     | √                               | √                      | ×                                   |
| [IccTA](https://github.com/lilicoding/soot-infoflow-android-iccta) | √                              | 86           | √                                     | √                               | √                      | ×                                   |
| [Mallodroid](https://github.com/sfahl/mallodroid)            | √                              | 64           | √                                     | √                               | √                      | ×                                   |
| [SMV_Hunter](https://github.com/utds3lab/SMVHunter)          | √                              | 12           | √                                     | √                               | √                      | ×                                   |
| [ScanDroid](https://www.cs.umd.edu/~avik/papers/scandroidascaa.pdf) | √                              |              | √                                     | √                               | √                      | ×                                   |
| [TaintDroid](http://www.appanalysis.org/index.html)          | √                              |              | √                                     | √                               | √                      | ×                                   |
| Epicc                                                        | √                              |              | √                                     | √                               | √                      | ×                                   |
| DIDFail                                                      | √                              |              | √                                     | √                               | √                      | ×                                   |
| [Appshark](https://github.com/bytedance/appshark)            | √                              | 1.4k         | √                                     | √                               | √                      | ×                                   |
| [redos-detector](https://github.com/olivo/redos-detector)    | √                              | 32           | √                                     | √                               | √                      | ×                                   |
| [mariana-trench](https://github.com/facebook/mariana-trench) | √                              | 1k           | √                                     | √                               | √                      | ×                                   |
| [HybridFlow](https://github.com/yuanchun-li/HybridFlow)      | √                              | 14           | √                                     | √                               | √                      | ×                                   |
| [HybriDroid](https://github.com/SunghoLee/HybriDroid)        | √                              | 22           | √                                     | √                               | √                      | ×                                   |
| [Android SSL Vulnerability Detection Tools](https://github.com/grahamedgecombe/android-ssl) | √                              | 18           | √                                     | √                               | √                      | ×                                   |
| [BackDroid](https://github.com/VPRLab/BackDroid)             | √                              | 38           | √                                     | √                               | √                      | ×                                   |
| [PITracker](https://github.com/Sp1keeeee/PItracker)          | √                              | 12           | √                                     | √                               | √                      | ×                                   |

Finally, we obtained 11 Android SAST tools: MobSF, QARK, AndroBugs, APKHunt, SUPER, JAADAS, DroidStatx, Marvin, Trueseeing, AUSERA and SPECK:

| Tool Name                                                    | Free of charge and transparent | Github Stars | Available documentation and usability | Tools compatible with APK files | Command-line interface | Generalized vulnerability detection |
| ------------------------------------------------------------ | ------------------------------ | ------------ | ------------------------------------- | ------------------------------- | ---------------------- | ----------------------------------- |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) | √                              | 15.4k        | √                                     | √                               | √                      | √                                   |
| [QARK](https://github.com/linkedin/qark/)                    | √                              | 3.1k         | √                                     | √                               | √                      | √                                   |
| [AndroBugs](https://github.com/AndroBugs/AndroBugs_Framework) | √                              | 1.1k         | √                                     | √                               | √                      | √                                   |
| [APKHunt](https://github.com/Cyber-Buddy/APKHunt)            | √                              | 622          | √                                     | √                               | √                      | √                                   |
| [SUPER](https://github.com/SUPERAndroidAnalyzer/super)       | √                              | 411          | √                                     | √                               | √                      | √                                   |
| [JAADAS](https://github.com/flankerhqd/JAADAS)               | √                              | 338          | √                                     | √                               | √                      | √                                   |
| [Droidstatx](https://github.com/clviper/droidstatx)          | √                              | 115          | √                                     | √                               | √                      | √                                   |
| [Marvin](https://github.com/programa-stic/Marvin-static-Analyzer) | √                              | 68           | √                                     | √                               | √                      | √                                   |
| [Trueseeing](https://github.com/alterakey/trueseeing)        | √                              | 52           | √                                     | √                               | √                      | √                                   |
| [AUSERA](https://github.com/tjusenchen/AUSERA)               | √                              | 25           | √                                     | √                               | √                      | √                                   |
| [SPECK](https://github.com/SPRITZ-Research-Group/SPECK)      | √                              | 11           | √                                     | √                               | √                      | √                                   |




### REFERENCES

[1] NIST. 2023. Source Code Security Analyzers | NIST. https://www.nist.gov/itl/ssd/software-quality-group/source-code-security-analyzers. (Accessed on 07/19/2023).

[2] Gartner. 2023. Best Mobile App Security Testing Tools Reviews 2023 | Gartner Peer Insights. https://www.gartner.com/reviews/market/mobile-application-security-testing. (Accessed on 07/19/2023)

[3] 2023. Repository search results. https://github.com/search?q=Android+static+analysis&type=repositories&p=1. (Accessed on 12/14/2023).

[4] 2023. Repository search results. https://github.com/search?q=Android%20Vulnerabilities&type=repositories. (Accessed on 12/14/2023)

[5] Venkatesh-Prasad Ranganath and Joydeep Mitra. 2020. Are free Android app security analysis tools effective in detecting known vulnerabilities?Empirical Software Engineering 25 (2020), 178–219.

[6] Bradley Reaves, Jasmine Bowers, Sigmund Albert Gorski III, Olabode Anise, Rahul Bobhate, Raymond Cho, Hiranava Das, Sharique Hussain, Hamza Karachi-wala, Nolen Scaife, et al. 2016. * droid: Assessment and evaluation of android application analysis tools. ACM Computing Surveys (CSUR) 49, 3 (2016), 1–30.

[7] Janaka Senanayake, Harsha Kalutarage, Mhd Omar Al-Kadri, Andrei Petrovski, and Luca Piras. 2023. Android source code vulnerability detection: a systematic literature review. Comput. Surveys 55, 9 (2023), 1–37.

[8] Sen Chen, Yuxin Zhang, Lingling Fan, Jiaming Li, and Yang Liu. 2022. Ausera: Automated security vulnerability detection for Android apps. In Proceedings of the 37th IEEE/ACM International Conference on Automated Software Engineering. 1–5.
