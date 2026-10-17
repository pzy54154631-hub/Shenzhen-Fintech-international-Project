Planner: record
Scenario: J05/business_day_boundaries

- utc_midnight_keeps_total: PASS
- before_china_midnight: PASS
- china_midnight_resets: PASS
- yesterday_token_drift: PASS
- unknown_uses_dispatch_day: PASS
- audit_chain: PASS
