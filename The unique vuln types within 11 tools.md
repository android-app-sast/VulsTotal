# The unique vuln types within 11 tools
This file contains 11 tools uniquely supported vulnerability types and the corresponding OWASP Mobile Top 10 2024 categories (OWASP in short).
#### MobSF
| **Vulnerability Type Name** | **Corresponding OWASP Categories** |
| --- | --- |
| App_in_test_mode | M1: Improper Credential Usage |
| Task_affinity_set | M8: Security Misconfiguration |
| High_intent_priority_found | M8: Security Misconfiguration |
| High_action_priority_found | M8: Security Misconfiguration |
| Android_hiddenui | M6: Inadequate Privacy Controls |
| Android_weak_hash（md4） | M10: Insufficient Cryptography |
| Certificate algorithm might be vulnerable to hash collision | M10: Insufficient Cryptography |
| Missing Code Signing certificate | M8: Security Misconfiguration |
| Certificate pinning expires on {exp}. After this date'pinning will be disabled | M5: Insecure Communication |
| Application vulnerable to Janus Vulnerability | M4: Insufficient Input/Output Validation |
| Base config is configured to bypass certificate pinning. | M5: Insecure Communication |
| Domain config is configured to bypass certificate pinning. | M5: Insecure Communication |
| Base config is configured to trust bundled certs | M5: Insecure Communication |
| Base config is configured to trust system certificates | M5: Insecure Communication |
| Domain config is configured to trust bundled certs | M5: Insecure Communication |
| Domain config is configured to trust system certificates | M5: Insecure Communication |

#### QARK
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| LOGS_WR | M8: Security Misconfiguration |
| DOM_STORAGE_EN(DOM Storage WebView) | M8: Security Misconfiguration |

#### AndroBugs
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| HTTPURLCONNECTION_BUG | M5: Insecure Communication |
| DB_SQLITE_JOURNAL | M9: Insecure Data Storage |
| PERMISSION_INTENT_FILTER_MISCONFIG | M8: Security Misconfiguration |
| FILE_DELETE | M8: Security Misconfiguration |
| HACKER_KEYSTORE_NO_PWD | M1: Improper Credential Usage  |

#### APKHunt
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| The Local Storage - Input Validation... | M4: Insufficient Input/Output Validation |
| The Push Notification instances... | M6: Inadequate Privacy Controls |
| The Keyboard Cache instances... | M9: Insecure Data Storage  |
| The Sensitive Data Disclosure through the User Interface... | M6: Inadequate Privacy Controls |
| The flush instances utilized for clearing the Memory... | M8: Security Misconfiguration |
| The cookie related instances... | M5: Insecure Communication |
| The Weak SSL/TLS protocols... | M5: Insecure Communication |
| The Security Provider implementation... | M8: Security Misconfiguration |
| The potential Cross-Site Scripting flaws... | M4: Insufficient Input/Output Validation  |
| The EnableSafeBrowsing setting... | M8: Security Misconfiguration |
| The instances of URL Loading in WebViews... | M5: Insecure Communication |
| The Custom URL Schemes... | M8: Security Misconfiguration |
| The Object Persistence/Serialization instances... | M9: Insecure Data Storage |

#### SUPER
**None**
#### JAADAS
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| intent parseUri | M4: Insufficient Input/Output Validation |
| FAKEID reloaded vulnerability | M8: Security Misconfiguration |
| Scan for ZipEntry vulnerable to unzip directory traversal vulnerability | M4: Insufficient Input/Output Validation |

#### DroidStatx
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| pinningExpiration | M5: Insecure Communication |
| encryptionFunctionsLocation | M10: Insufficient Cryptography |
| decryptionFunctionsLocation | M10: Insufficient Cryptography |
| undeterminedCryptographicFunctionsLocation | M10: Insufficient Cryptography |
| okHttpCertificatePinningLocation | M5: Insecure Communication |
| vulnerableContentProvidersSQLiLocations | M4: Insufficient Input/Output Validation |

#### Marvin
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| Low number of iterations of PBE ==>CRYPTOGRAPHY | M10: Insufficient Cryptography |
| AUTOCOMPLETE_PASSWORD_INPUT | M6: Inadequate Privacy Controls |
| SURREPTITIOUS_SHARING | M6: Inadequate Privacy Controls |

#### Trueseeing
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| insecure cryptography: static keys | M10: Insufficient Cryptography |
| Detects Vernum cipher usage with static keys | M10: Insufficient Cryptography |
| Detects potential client-side XSS vector in JQuery-based apps | M4: Insufficient Input/Output Validation |
| Detects format string usages | M4: Insufficient Input/Output Validation |
| insecure TLS connection no pinning detected | M5: Insecure Communication |

#### AUSERA
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| Text file leakage | M9: Insecure Data Storage |

#### SPECK
| Vulnerability Type Name | **Corresponding OWASP Categories** |
| --- | --- |
| Access device encrypted storage | M9: Insecure Data Storage |
| Migrate existing data | M8: Security Misconfiguration |
| Deprecated cryptographic functionality | M10: Insufficient Cryptography  |
| Share data securely across apps | M6: Inadequate Privacy Controls |

