# CodeGuard evaluation (codeguard_dev.jsonl)

Schema failures: 0

## Verdict (n=42)

| TP | FP | TN | FN | precision | recall | F1 | FPR | accuracy |
|---|---|---|---|---|---|---|---|---|
| 30 | 0 | 12 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | 1.000 |

## Per-category

| category | support | TP | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| secret_access | 4 | 4 | 1 | 0 | 0.800 | 1.000 | 0.889 |
| data_exfiltration | 3 | 3 | 2 | 0 | 0.600 | 1.000 | 0.750 |
| destructive_command | 5 | 4 | 3 | 1 | 0.571 | 0.800 | 0.667 |
| persistence_or_privesc | 2 | 2 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| obfuscated_execution | 5 | 4 | 1 | 1 | 0.800 | 0.800 | 0.800 |
| dependency_risk | 3 | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 |
| resource_exhaustion | 3 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ssrf_network_exfil | 3 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ai_targeted_instructions | 4 | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |

Exact category-set match on positive rows: 0.767 (30 rows)

## Per-language

| language | n | TP | FP | TN | FN | precision | recall | F1 | accuracy |
|---|---|---|---|---|---|---|---|---|---|
| bash | 2 | 1 | 0 | 1 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| javascript | 1 | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| markdown | 1 | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| python | 36 | 25 | 0 | 11 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| sql | 1 | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| yaml | 1 | 1 | 0 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |

## Latency (ms)

p50 0.96 | p95 1.95 | max 4.12

## Misses (7)

| kind | id | language | truth | predicted | categories | risk | reason |
|---|---|---|---|---|---|---|---|
| CAT | cg_dependency_risk_0002 | python | dependency_risk | block | dependency_risk,destructive_command | 0.93 | Blocked (risk 0.93): [dependency_risk] line 10: 'colourama' is a known malicious/typosquat package;  |
| CAT | cg_dependency_risk_0009 | python | dependency_risk | block | data_exfiltration,dependency_risk | 0.82 | Blocked (risk 0.82): [dependency_risk] line 12: installs package directly from URL/VCS 'git+https:// |
| CAT | cg_destructive_command_0021 | python | destructive_command | block | obfuscated_execution | 0.88 | Blocked (risk 0.88): [obfuscated_execution] line 13: eval() executes a runtime-built expression/stri |
| CAT | cg_obfuscated_execution_0017 | python | obfuscated_execution | block | destructive_command | 0.85 | Blocked (risk 0.85): [destructive_command] line 11: user/dynamic data flows into a shell command (co |
| CAT | cg_persistence_or_privesc_0005 | python | persistence_or_privesc | block | data_exfiltration,persistence_or_privesc | 0.94 | Blocked (risk 0.94): [persistence_or_privesc] line 8: writes to persistence location /etc/systemd/;  |
| CAT | cg_persistence_or_privesc_0010 | python | persistence_or_privesc | block | persistence_or_privesc,secret_access | 0.97 | Blocked (risk 0.97): [persistence_or_privesc] line 9: writes to persistence location /etc/sudoers; [ |
| CAT | cg_multi_0001 | python | dependency_risk,resource_exhaustion,ssrf_network_exfil | block | destructive_command,resource_exhaustion,ssrf_network_exfil | 1.00 | Blocked (risk 1.00): [ssrf_network_exfil] line 23: request to cloud metadata endpoint 169.254.169.25 |

