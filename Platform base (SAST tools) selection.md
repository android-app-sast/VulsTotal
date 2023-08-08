# Platform Base (SAST Tools) Selection

​To construct a unified platform and thoroughly evaluate the detection capabilities of Android SAST tools, we sought out a diverse set of SAST tools from both academic and industrial domains. 

​To gather this information, we primarily searched tools from recent literature and two prominent websites including NIST and Gartner. Then we snowballed from them since they also recommend further lists. 

​After collating data from these diverse sources, we were able to identify 43 pertinent SAST tools in the domain of Android security, spanning both industry and academia. 

### Tools Sources:

​We list the SAST tools from different sources as follows:

#### NIST[1] (2):

|      | Tool Name   | Notes                                                        | Resource                                                     |
| ---- | ----------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | OVERSECURED | Oversecured, a mobile app vulnerability scanner, designed for DevOps process integration, that is built to protect customers' privacy and defend their devices against modern threats.Available for iOS/Android apps | https://oversecured.com/                                     |
| 2    | Veracode    | Rapidly find and fix vulnerabilities with real-time feedback and reduce flaws introduced in new code by up to 60% with IDE scans | https://www.veracode.com/products/binary-static-analysis-sast |

#### Gartner[2] (22):

|      | Tool Name                             | Notes                                                        | Resource                                                     |
| ---- | ------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | App-ray                               | App-Ray Static Analysis (SAST) and Dynamic Analysis (DAST) provides actionable results with 80+ types of security vulnerabilities, data management and privacy issues to identify | https://app-ray.co/                                          |
| 2    | Codified Security                     | Codified is the world's most popular testing platform for mobile application software which make it easier than ever for companies to detect and fix security vulnerabilities and ensure their applications are regulatory compliant. Discover and fix user mobile application security risks today with smart test technology platform. | https://codifiedsecurity.com/                                |
| 3    | Quixxi                                | Quixxi is an intelligent and integrated end-to-end mobile app security solution. This powerful tool is for developers to protect and monitor any mobile app in minutes. | https://quixxisecurity.com/                                  |
| 4    | ImmuniWeb MobileSuite                 | Detect OWASP Mobile Top 10 weaknesses in all mobile apps with ImmuniWeb Discovery mobile security scanning. | https://www.immuniweb.com/use-cases/#mobile-security-scanning |
| 6    | appknox                               | SAST, DAST, and API Scans Launch the holistic vulnerability assessment with a one-click static scan after uploading mobile app's binary. | https://www.appknox.com/                                     |
| 7    | Fortify on Demand                     | Fortify on Demand is the application security provider to offer SAST, SCA, DAST, IAST, and MAST as a service. | https://www.microfocus.com/en-us/cyberres/application-security/fortify-on-demand |
| 8    | Synopsys                              | Synopsys Mobile Application Security Testing (MAST) enables users to implement client-side code, server-side code, and third-party library analysis quickly so users can systematically find and fix security vulnerabilities in mobile applications, without the need for source code. | https://www.synopsys.com/software-integrity/application-security-testing-services/mobile-application-security-testing.html |
| 9    | Checkmarx SAST                        | Checkmarx Static Application Security Testing (SAST) provides fast and accurate incremental or full scans and gives users the flexibility, accuracy, integrations, and coverage to secure moblie applications | https://checkmarx.com/product/cxsast-source-code-scanning/   |
| 10   | eschecker                             | esChecker performs mobile application security testing at the binary level, where all the resources of the app are compiled and packaged, including 3rd parties SDK which source code review doesn’t take into consideration. | https://eshard.com/eschecker                                 |
| 11   | nowsecure                             | NowSecure enables standards-based mobile app security testing and certification including OWASP MASVS, ADA MASA, ioXt, NIAP and more. | https://www.nowsecure.com/                                   |
| 12   | Testhouse Managed Testing Services    | Testhouse has a dedicated mobile testing practise to test applications across operating systems (iOS, Android and others) and their versions. Their testing practise will make sure  application will work flawlessly across all mobile devices and platforms, delivering exceptional user experience. | https://www.testhouse.net/service-offerings/digital-assurance/mobility/ |
| 13   | Data Theorem Mobile Secure            | The Analyzer Engine will run a series of static and dynamic analyses for users' uploading applications, accounting for both backend APIs as well as third-party code. | https://www.datatheorem.com/products/mobile-secure           |
| 14   | pradeo                                | Pradeo’s mobile threat detection technology leans on a patented Artificial Intelligence process that precisely reveals and qualifies behaviors and vulnerabilities. Along the years, the Pradeo Security mobile application security testing  platform has identified billions of behaviors and vulnerabilities. | https://www.pradeo.com/en-US/mobile-application-security-testing |
| 15   | Appthority MTP                        | MTP Manager has a Dashboard that gives quick summaries of mobile threat detection status for the Organization. | https://help-mtp.appthority.com/WelcomeToMTP.html            |
| 16   | derscanner                            | DerScanner is a convenient and easy-to-use officially CWE-Compatible solution that combines the capabilities of static (SAST), dynamic (DAST) and software composition analysis (SCA) in a single interface. | https://derscanner.com/                                      |
| 17   | Entersoft Mobile Application Security | Entersoft's SAST methodology is a powerful solution for identifying potential security vulnerabilities within applications' source code. Our SAST approach provides a comprehensive analysis of your codebase, examining it line by line, to identify and remediate any potential weaknesses that could be exploited by attackers. | https://entersoftsecurity.com/mobile-app-security            |
| 18   | Kryptowire                            | Kryptowire(Quokka)MAST’s unique combination of advanced analysis engines digs deeper and tests more thoroughly than any other MAST solution on the market. Our combination of using SAST, DAST and IAST, plus extensive proprietary engines that go beyond these common methodologies enabling the discovery of more CVEs than any other application security company. | https://www.quokka.io/solutions/mobile-app-security-testing  |
| 19   | Varutra                               | Varutra provide Mobile Application Security Services across different platforms such as - Android, i0S of type Native, Hybrid, Web as well as Mobile Device Management apps. | https://www.varutra.com/cyber-security-services/mobile-applications-security/ |
| 20   | Zimperium zScan                       | zScan leverages machine learning and rulesets for uncovering latent issues and support tailor scans to focus on specific areas of concern | https://www.zimperium.com/zscan/                             |
| 21   | AppSonar                              | AppSonar is a security testing software that helps improve the security and quality of your applicationThe test rules are based on industry standards including but not limited to OWASP Top 10, CWE/SANS-25 and NIST. | https://www.appsonar.com/                                    |
| 22   | Appsweep                              | Quickly find & solve security issues in your mobile app’s code and dependencies, based on security standards (e.g. OWASP MASVS ). Actionable recommendations enable quick resolution, keeping launches on time and on budget. And it is free. | https://appsweep.guardsquare.com/                            |

#### Ranganath[3] (7):

|      | Tool Name  | Notes                                                        | Resource                                                     |
| ---- | ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | AndroBugs  | AndroBugs Frameworkis an Android vulnerability static analysis system that helps developers or hackers find potential security vulnerabilities in Android applications. No splendid GUI interface, but the most efficient and more accurate. | https://github.com/AndroBugs/AndroBugs_Framework             |
| 2    | MobSF      | MobSF is an automatic,open-source and integrated framework for mobile application penetration testing, malware analysis and security assessment, capable of performing static and dynamic analysis. | https://github.com/MobSF/Mobile-Security-Framework-MobSF     |
| 3    | Qark       | QARK can look for security related Android application vulnerabilities with source code and packaged APKs as input. QARK provides the ability to create 'Proof-of-Concept' deployable APKs and/or ADB commands, capable of exploiting many of the vulnerabilities it finds, which can help verify potential vulnerabilities it detects. | https://github.com/linkedin/qark                             |
| 4    | JAADAS     | JAADAS is a Joint Advanced Defect Assessment framework for Android applications which provides inter-procedure and intra-procedure static analysis for Android applications. | https://github.com/flankerhqd/JAADAS                         |
| 5    | Marvin     | Marvin static analyzer is an Android application vulnerability scanning tool.  The Marvin tool utilizes the Androguard and Static Android Analysis Framework (SAAF) frameworks. | https://github.com/programa-stic/Marvin-static-Analyzer      |
| 6    | IccTA      | IccTA can detecting inter-component privacy leaks in Android app | ICSE'15, Detecting Inter-Component Privacy Leaks in Android Apps |
| 7    | SMV-Hunter | a system for the automatic, large-scale identification of such vulnerabilities that combines both static and dynamic analysis. | NDSS'14, Smv-hunter: Large scale, automated detection of ssl/tls man-in-the-middle vulnerabilities in android apps |

#### Reaves[4] (3):

|      | Tool Name | Notes                                                        | Resource                                                     |
| ---- | --------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | AmanDroid | Ability to analyse the inter-component data low for security vetting.Unable to detect security issues where exceptions can occur and unable to handle relections and concurrency. | TOPS'18, Amandroid: A precise and general inter-component data flow analysis framework for security vetting of android apps, |
| 2    | DroidSafe | DroidSafe is a static application analysis tool designed to analyze malicious information flows in Android source code and APK files. | [NDSS'15, Information flow analysis of android applications in droidsafe;   https://github.com/MIT-PAC/droidsafe-src](https://github.com/MIT-PAC/droidsafe-src) |
| 3    | FixDroid  | FixDroid is an Android Studio plugin. As long as FixDroid is installed, it will keep providing you with helpful security alerts, explanations and quick fixes whenever possible | CCS'17, A stitch in time: Supporting android developers in writing secure code |



#### Senanayake[5] (5):

|      | Tool Name  | Notes                                                        | Resource                                                     |
| ---- | ---------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | DIALDroid  | Ability to identify privilege escalations and inter-app collusion.Unable to resolve relective calls if their arguments do not contain string constants and may fail to compute some ICC links due to ignoring over-approximated regular expressions. | AsiaCCS'17, Collusive data leak and more: Large-scale threat analysis of inter-app communications |
| 2    | MalloDroid | Ability to identify broken SSL certiication validation using Androgurd framework | CCS'12, Why eve and mallory love android: An analysis of android ssl (in)security |
| 3    | HornDroid  | Ability to perform static analysis of information lows, and ability to soundly abstract the semantic of Android apps to compose security properties. | EuroS&P'16, Horndroid: Practical and sound static analysis of android applications by SMT solving |
| 4    | COVERT     | Ability to perform compositional analysis of inter-app vulnerabilities.Unable to identify native code-related vulnerabilities and Permission leakages. | TSE'15, COVERT: Compositional Analysis of Android Inter-App Permission Leakage |
| 5    | CogniCrypt | CrySL [13] is a domain-specific language for cryptographic libraries.The static analysis CogniCryptSAST takes the rules provided in the specification language CrySL as input, and performs a static analysis based on the specification of the rules. | [ECOOP'18, CrySL: An Extensible Approach to Validating the Correct Usage of Cryptographic APIs;  https://github.com/CROSSINGTUD/CryptoAnalysis](https://github.com/CROSSINGTUD/CryptoAnalysis) |

#### Zhang[6] (1):

|      | Tool Name     | Notes                                                        | Resource                                                     |
| ---- | ------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | **FlowDroid** | FlowDroid statically computes data flows in Android apps and Java programs.But assumes that the entire contents remain tainted, even if an untainted value overwrites the single array element. | PLDI‘14, FlowDroid: Precise Context, Flow, Field, Object-sensitive and Lifecycle-aware Taint Analysis for Android Apps |

#### Chen[7] (2):

|      | Tool Name | Notes                                                        | Resource                                                     |
| ---- | --------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| 1    | AUSERA    | AUSERA is an automated security risk assessment tool for Android application vulnerability detection. It uses static program analysis, such as data flow and control flow analysis, sensitive data labeling, function identification, etc., to automatically detect vulnerabilities in Android applications | ASE'22, AUSERA: Automated Security Vulnerability Detection for Android Apps; https://github.com/tjusenchen/AUSERA |
| 2    | SUPER     | SUPER is a command line application which look for security related vulnerabilities for Android applications. RUST is used as its programming language, and therefore the tool can be extended. In addition, because it is a modular writing rules, so the user can customize the rules. | https://github.com/SUPERAndroidAnalyzer/super                |

#### Others (1):

|      | Tool Name | Notes                                                        | Resource                                       |
| ---- | --------- | ------------------------------------------------------------ | ---------------------------------------------- |
| 1    | SPECK     | SPECK is a tool for searching for multiple bad codes in Android applications. From the Android documentation, developers extracted a set of rules to follow to improve app security. It performs static analysis by viewing the application source code to detect rule violations. | https://github.com/SPRITZ-Research-Group/SPECK |

​	We obtained a total of 43 SAST tools through the above sources.

### Tools Selection:

​	To facilitate the selection and comparison of Android SAST tools for our study, we then designed 3 selection criteria as follows:

- Free of charge and transparent; 
- Generalized vulnerability detection; 
- Proven ability to detect synthetic vulnerabilities

​	We showed the detailed details of the three selection criteria of all the tools in the following table.

|      | Tool Name                             | Free of charge and transparent | Generalized vulnerability detection | Proven ability to detect synthetic vulnerabilities |
| ---- | ------------------------------------- | ------------------------------ | ----------------------------------- | -------------------------------------------------- |
| 1    | App-ray                               | ×                              | √                                   | √                                                  |
| 2    | Codified Security                     | ×                              | √                                   | √                                                  |
| 3    | Quixxi                                | ×                              | √                                   | √                                                  |
| 4    | ImmuniWeb MobileSuite                 | ×                              | √                                   | √                                                  |
| 5    | OVERSECURED                           | ×                              | √                                   | √                                                  |
| 6    | appknox                               | ×                              | √                                   | √                                                  |
| 7    | Fortify on Demand                     | ×                              | √                                   | √                                                  |
| 8    | Synopsys                              | ×                              | √                                   | √                                                  |
| 9    | Veracode                              | ×                              | √                                   | √                                                  |
| 10   | Checkmarx SAST                        | ×                              | √                                   | √                                                  |
| 11   | eschecker                             | ×                              | √                                   | √                                                  |
| 12   | nowsecure                             | ×                              | √                                   | √                                                  |
| 13   | Testhouse Managed Testing Services    | ×                              | √                                   | √                                                  |
| 14   | Data Theorem Mobile Secure            | ×                              | √                                   | √                                                  |
| 15   | pradeo                                | ×                              | √                                   | √                                                  |
| 16   | Appthority MTP                        | ×                              | √                                   | √                                                  |
| 17   | derscanner                            | ×                              | √                                   | √                                                  |
| 18   | Entersoft Mobile Application Security | ×                              | √                                   | √                                                  |
| 19   | Kryptowire                            | ×                              | √                                   | √                                                  |
| 20   | Varutra                               | ×                              | √                                   | √                                                  |
| 21   | Zimperium zScan                       | ×                              | √                                   | √                                                  |
| 22   | AppSonar                              | ×                              | √                                   | √                                                  |
| 23   | Appsweep                              | ×                              | √                                   | √                                                  |
| 24   | AUSERA                                | √                              | √                                   | √                                                  |
| 25   | Androbugs                             | √                              | √                                   | √                                                  |
| 26   | MobSF                                 | √                              | √                                   | √                                                  |
| 27   | Qark                                  | √                              | √                                   | √                                                  |
| 28   | SUPER                                 | √                              | √                                   | √                                                  |
| 29   | JAADAS                                | √                              | √                                   | √                                                  |
| 30   | Marvin                                | √                              | √                                   | √                                                  |
| 31   | SPECK                                 | √                              | √                                   | √                                                  |
| 32   | StaCoAn                               | √                              | √                                   | ×                                                  |
| 33   | FlowDroid                             | √                              | ×                                   | √                                                  |
| 34   | IccTA                                 | √                              | ×                                   | √                                                  |
| 35   | AmanDroid                             | √                              | ×                                   | √                                                  |
| 36   | DroidSafe                             | √                              | ×                                   | √                                                  |
| 37   | FixDroid                              | ×                              | √                                   | √                                                  |
| 38   | SMV-Hunter                            | √                              | ×                                   | √                                                  |
| 39   | DIALDroid                             | √                              | ×                                   | √                                                  |
| 40   | MalloDroid                            | √                              | ×                                   | √                                                  |
| 41   | HornDroid                             | √                              | ×                                   | √                                                  |
| 42   | COVERT                                | √                              | ×                                   | √                                                  |
| 43   | CogniCrypt                            | √                              | ×                                   | √                                                  |

In terms of 'Free of charge and transparent', the Android SAST tools must be free of charge. While commercial tools are indeed prevalent in the industry, they often entail substantial costs, which would be prohibitive for our large-scale experiment. Additionally, since we try to explore the internal implementation of the tool candidates, we filtered out 24 tools that are not transparent or free such as Quixxi, ImmuniWeb, and Checkmarx SAST. 

​The remaining 19 SAST tools are as follows:

|      | Tool Name  | Free of charge and transparent | Generalized vulnerability detection | Proven ability to detect synthetic vulnerabilities |
| ---- | ---------- | ------------------------------ | ----------------------------------- | -------------------------------------------------- |
| 1    | AUSERA     | √                              | √                                   | √                                                  |
| 2    | Androbugs  | √                              | √                                   | √                                                  |
| 3    | MobSF      | √                              | √                                   | √                                                  |
| 4    | Qark       | √                              | √                                   | √                                                  |
| 5    | SUPER      | √                              | √                                   | √                                                  |
| 6    | JAADAS     | √                              | √                                   | √                                                  |
| 7    | Marvin     | √                              | √                                   | √                                                  |
| 8    | SPECK      | √                              | √                                   | √                                                  |
| 9    | StaCoAn    | √                              | √                                   | ×                                                  |
| 10   | FlowDroid  | √                              | ×                                   | √                                                  |
| 11   | IccTA      | √                              | ×                                   | √                                                  |
| 12   | AmanDroid  | √                              | ×                                   | √                                                  |
| 13   | DroidSafe  | √                              | ×                                   | √                                                  |
| 14   | SMV-Hunter | √                              | ×                                   | √                                                  |
| 15   | DIALDroid  | √                              | ×                                   | √                                                  |
| 16   | MalloDroid | √                              | ×                                   | √                                                  |
| 17   | HornDroid  | √                              | ×                                   | √                                                  |
| 18   | COVERT     | √                              | ×                                   | √                                                  |
| 19   | CogniCrypt | √                              | ×                                   | √                                                  |

​In terms of 'Generalized vulnerability detection'. Since we aim to understand the extent of coverage for various types of vulnerabilities by current Android SAST tools. Thus, it is crucial that the selected tools can identify a wide range of Android vulnerabilities. Thus, we excluded 10 tools that are designed to detect specific vulnerability types, such as SMV-Hunter(detecting SSL/TLS MITM vulnerabilities), CogniCrypt (detecting vulnerable cryptographic API usage), and FlowDroid (Taint analysis). 

​The remaining 9 SAST tools are as follows:

|      | Tool Name | Free of charge and transparent | Generalized vulnerability detection | Proven ability to detect synthetic vulnerabilities |
| ---- | --------- | ------------------------------ | ----------------------------------- | -------------------------------------------------- |
| 1    | AUSERA    | √                              | √                                   | √                                                  |
| 2    | Androbugs | √                              | √                                   | √                                                  |
| 3    | MobSF     | √                              | √                                   | √                                                  |
| 4    | Qark      | √                              | √                                   | √                                                  |
| 5    | SUPER     | √                              | √                                   | √                                                  |
| 6    | JAADAS    | √                              | √                                   | √                                                  |
| 7    | Marvin    | √                              | √                                   | √                                                  |
| 8    | SPECK     | √                              | √                                   | √                                                  |
| 9    | StaCoAn   | √                              | √                                   | ×                                                  |

​In terms of the 'Proven ability to detect synthetic vulnerabilities'. To facilitate the comparison and evaluation of tool effectiveness between synthetic and real-world benchmarks, it is required that tools should demonstrate an ability to detect vulnerabilities in synthetic benchmarks such as GHERA, i.e., be able to detect at least one vulnerability type. Thus, we excluded Stacoan, which failed to identify any synthetic vulnerabilities. 

​The final 8 selected SAST tools are as follows:

|      | Tool Name | Free of charge and transparent | Generalized vulnerability detection | Proven ability to detect synthetic vulnerabilities |
| ---- | --------- | ------------------------------ | ----------------------------------- | -------------------------------------------------- |
| 1    | AUSERA    | √                              | √                                   | √                                                  |
| 2    | Androbugs | √                              | √                                   | √                                                  |
| 3    | MobSF     | √                              | √                                   | √                                                  |
| 4    | QARK      | √                              | √                                   | √                                                  |
| 5    | SUPER     | √                              | √                                   | √                                                  |
| 6    | JAADAS    | √                              | √                                   | √                                                  |
| 7    | Marvin    | √                              | √                                   | √                                                  |
| 8    | SPECK     | √                              | √                                   | √                                                  |


### REFERENCES

[1] NIST. 2023. Source Code Security Analyzers | NIST. https://www.nist.gov/itl/ssd/software-quality-group/source-code-security-analyzers. (Accessed on 07/19/2023).

[2] Gartner. 2023. Best Mobile App Security Testing Tools Reviews 2023 | Gartner Peer Insights. https://www.gartner.com/reviews/market/mobile-application-security-testing. (Accessed on 07/19/2023)

[3] Venkatesh-Prasad Ranganath and Joydeep Mitra. 2020. Are free Android app security analysis tools effective in detecting known vulnerabilities?Empirical Software Engineering 25 (2020), 178–219.

[4] Bradley Reaves, Jasmine Bowers, Sigmund Albert Gorski III, Olabode Anise, Rahul Bobhate, Raymond Cho, Hiranava Das, Sharique Hussain, Hamza Karachi-wala, Nolen Scaife, et al. 2016. * droid: Assessment and evaluation of android application analysis tools. ACM Computing Surveys (CSUR) 49, 3 (2016), 1–30.

[5] Janaka Senanayake, Harsha Kalutarage, Mhd Omar Al-Kadri, Andrei Petrovski, and Luca Piras. 2023. Android source code vulnerability detection: a systematic literature review. Comput. Surveys 55, 9 (2023), 1–37.

[6] Junbin Zhang, Yingying Wang, Lina Qiu, and Julia Rubin. 2021. Analyzing Android taint analysis tools: FlowDroid, Amandroid, and DroidSafe. IEEE Trans-actions on Software Engineering 48, 10 (2021), 4014–4040.

[7] Sen Chen, Yuxin Zhang, Lingling Fan, Jiaming Li, and Yang Liu. 2022. Ausera: Automated security vulnerability detection for Android apps. In Proceedings of the 37th IEEE/ACM International Conference on Automated Software Engineering. 1–5.
