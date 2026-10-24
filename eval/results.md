# CodeGuard evaluation (holdout2.jsonl)

Schema failures: 0

## Verdict (n=30)

| TP | FP | TN | FN | precision | recall | F1 | FPR | accuracy |
|---|---|---|---|---|---|---|---|---|
| 12 | 2 | 13 | 3 | 0.857 | 0.800 | 0.828 | 0.133 | 0.833 |

## Per-category

| category | support | TP | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| secret_access | 2 | 1 | 0 | 1 | 1.000 | 0.500 | 0.667 |
| data_exfiltration | 3 | 3 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| destructive_command | 2 | 1 | 1 | 1 | 0.500 | 0.500 | 0.500 |
| persistence_or_privesc | 3 | 2 | 0 | 1 | 1.000 | 0.667 | 0.800 |
| obfuscated_execution | 2 | 2 | 1 | 0 | 0.667 | 1.000 | 0.800 |
| dependency_risk | 1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| resource_exhaustion | 1 | 1 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| ssrf_network_exfil | 2 | 1 | 1 | 1 | 0.500 | 0.500 | 0.500 |
| ai_targeted_instructions | 1 | 0 | 0 | 1 | 0.000 | 0.000 | 0.000 |

Exact category-set match on positive rows: 0.600 (15 rows)

## Per-language

| language | n | TP | FP | TN | FN | precision | recall | F1 | accuracy |
|---|---|---|---|---|---|---|---|---|---|
| python | 30 | 12 | 2 | 13 | 3 | 0.857 | 0.800 | 0.828 | 0.833 |

## Latency (ms)

p50 0.28 | p95 4.50 | max 542.09

## Misses (8)

| kind | id | language | truth | predicted | categories | risk | reason |
|---|---|---|---|---|---|---|---|
| CAT | hold2_000 | python | data_exfiltration,secret_access | block | data_exfiltration | 0.89 | Blocked (risk 0.89): [data_exfiltration] line 3: request to suspicious destination sink.evil.example |
| FN | hold2_004 | python | persistence_or_privesc | allow | - | 0.00 | Allowed (risk 0.00): no high-risk behavior detected |
| FN | hold2_007 | python | ssrf_network_exfil | allow | - | 0.00 | Allowed (risk 0.00): no high-risk behavior detected |
| CAT | hold2_008 | python | dependency_risk | block | dependency_risk,ssrf_network_exfil | 0.82 | Blocked (risk 0.82): [dependency_risk] line 1: installs from non-default package index/host 'http:// |
| CAT | hold2_009 | python | data_exfiltration,destructive_command | block | data_exfiltration | 0.80 | Blocked (risk 0.80): [data_exfiltration] line 2: nc streams local data or a shell to a remote host |
| FN | hold2_011 | python | ai_targeted_instructions | allow | - | 0.00 | Allowed (risk 0.00): no high-risk behavior detected |
| FP | hold2_018 | python | benign | block | destructive_command | 0.95 | Blocked (risk 0.95): [destructive_command] line 1: DELETE built by string concatenation (injectable, |
| FP | hold2_020 | python | benign | block | obfuscated_execution | 0.86 | Blocked (risk 0.86): [obfuscated_execution] line 2: compile() of a runtime-built string |

