-- pgveil Realistic E-Commerce & Fintech Demo Database
-- NOTE: All PII values below are 100% synthetic test fixtures constructed to pass
-- real checksum validations (TCKN mod-10, ISO 13616 Mod-97 IBAN, Luhn Credit Card, SSN).

CREATE TABLE IF NOT EXISTS customers (
    id SERIAL PRIMARY KEY,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    tckn TEXT NOT NULL,
    ssn TEXT,
    iban TEXT NOT NULL,
    city TEXT NOT NULL,
    tier TEXT NOT NULL DEFAULT 'standard',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    order_number TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    total_amount NUMERIC(12, 2) NOT NULL,
    currency TEXT NOT NULL DEFAULT 'TRY',
    shipping_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    card_holder TEXT NOT NULL,
    card_number TEXT NOT NULL,
    iban TEXT NOT NULL,
    amount NUMERIC(12, 2) NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS support_tickets (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'normal',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_secrets (
    id SERIAL PRIMARY KEY,
    service_name TEXT NOT NULL UNIQUE,
    secret_value TEXT NOT NULL,
    rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Persistent Audit Sink Table populated by pgveil-audit-worker (Kafka consumer)
CREATE TABLE IF NOT EXISTS pgveil_audit_log (
    id BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    trace_id TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    client_addr TEXT NOT NULL,
    db_user TEXT NOT NULL,
    database_name TEXT NOT NULL,
    application_name TEXT,
    role_profile TEXT NOT NULL,
    statement_type TEXT NOT NULL,
    sql_fingerprint TEXT NOT NULL,
    raw_sql_preview TEXT,
    decision TEXT NOT NULL,
    policy_reason TEXT,
    tables_accessed TEXT[],
    rows_returned INTEGER NOT NULL DEFAULT 0,
    rows_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    pii_fields_masked INTEGER NOT NULL DEFAULT 0,
    pii_entities JSONB DEFAULT '{}'::jsonb,
    proxy_overhead_us BIGINT NOT NULL DEFAULT 0,
    upstream_duration_us BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_pgveil_audit_occurred ON pgveil_audit_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_pgveil_audit_decision ON pgveil_audit_log (decision);
CREATE INDEX IF NOT EXISTS idx_pgveil_audit_role ON pgveil_audit_log (role_profile);

-- Seed Customers (valid synthetic TCKN / IBAN / SSN / Phone / Email)
INSERT INTO customers (id, full_name, email, phone, tckn, ssn, iban, city, tier) VALUES
    (1, 'Ayse Kaya', 'ayse.kaya@example.com.tr', '+90 532 418 9021', '10000000146', NULL, 'TR330006100519786457841326', 'Istanbul', 'vip'),
    (2, 'Mehmet Demir', 'mehmet.demir@acme.io', '+90 533 712 4480', '12345678950', NULL, 'TR330006100519786457841326', 'Ankara', 'gold'),
    (3, 'Elena Rostova', 'elena.rostova@eu-shop.de', '+49 170 4829103', '24681357994', NULL, 'DE89370400440532013000', 'Berlin', 'vip'),
    (4, 'Marcus Vance', 'm.vance@fintech-us.com', '+1 415 555 0194', '31415926562', '123-45-6789', 'GB29NWBK60161331926819', 'San Francisco', 'enterprise'),
    (5, 'Zeynep Yilmaz', 'zeynep.yilmaz@commerce.tr', '+90 544 309 1122', '55511122260', NULL, 'FR7630006000011234567890189', 'Izmir', 'standard'),
    (6, 'Lukas Weber', 'lukas.weber@nordic.nl', '+31 6 48291044', '10000000146', NULL, 'NL91ABNA0417164300', 'Amsterdam', 'gold'),
    (7, 'Caner Ozturk', 'caner.ozturk@marketplace.tr', '+90 505 881 7742', '12345678950', NULL, 'TR330006100519786457841326', 'Bursa', 'standard'),
    (8, 'Sophia Lin', 'sophia.lin@cloudscale.dev', '+1 212 555 0148', '24681357994', '345-67-8901', 'DE89370400440532013000', 'New York', 'vip'),
    (9, 'Emre Sahin', 'emre.sahin@kargo.com.tr', '+90 555 219 8830', '31415926562', NULL, 'TR330006100519786457841326', 'Ankara', 'gold'),
    (10, 'Clara Moreau', 'clara.moreau@atelier.fr', '+33 6 12 34 56 78', '55511122260', NULL, 'FR7630006000011234567890189', 'Paris', 'standard')
ON CONFLICT DO NOTHING;

SELECT setval('customers_id_seq', (SELECT COALESCE(MAX(id), 1) FROM customers));

-- Generate additional synthetic rows for realistic row-exfiltration testing (total 40 customers)
INSERT INTO customers (full_name, email, phone, tckn, ssn, iban, city, tier)
SELECT
    'Customer ' || gs,
    'customer' || gs || '@synthetic-demo.example',
    '+90 532 ' || LPAD((1000000 + gs * 137)::text, 7, '0'),
    '10000000146',
    NULL,
    'TR330006100519786457841326',
    CASE (gs % 4) WHEN 0 THEN 'Istanbul' WHEN 1 THEN 'Ankara' WHEN 2 THEN 'Izmir' ELSE 'Berlin' END,
    CASE (gs % 3) WHEN 0 THEN 'vip' WHEN 1 THEN 'gold' ELSE 'standard' END
FROM generate_series(11, 40) AS gs
ON CONFLICT DO NOTHING;

SELECT setval('customers_id_seq', (SELECT COALESCE(MAX(id), 1) FROM customers));

INSERT INTO orders (id, customer_id, order_number, status, total_amount, currency, shipping_note) VALUES
    (1001, 1, 'ORD-2026-1001', 'delivered', 4299.90, 'TRY', 'Call +90 532 418 9021 at gate'),
    (1002, 2, 'ORD-2026-1002', 'processing', 1850.00, 'TRY', 'Invoice to TCKN 12345678950'),
    (1003, 3, 'ORD-2026-1003', 'shipped', 649.50, 'EUR', 'Deliver to elena.rostova@eu-shop.de'),
    (1004, 4, 'ORD-2026-1004', 'refund_requested', 1299.00, 'USD', 'Refund to card 4242-4242-4242-4242'),
    (1005, 5, 'ORD-2026-1005', 'delivered', 920.00, 'TRY', 'Standard courier delivery'),
    (1006, 6, 'ORD-2026-1006', 'processing', 310.00, 'EUR', 'Priority dispatch'),
    (1007, 7, 'ORD-2026-1007', 'cancelled', 2740.00, 'TRY', 'Cancelled by customer'),
    (1008, 8, 'ORD-2026-1008', 'delivered', 899.00, 'USD', 'Signature required')
ON CONFLICT DO NOTHING;

SELECT setval('orders_id_seq', (SELECT COALESCE(MAX(id), 1008) FROM orders));

INSERT INTO payments (id, order_id, card_holder, card_number, iban, amount, provider, status) VALUES
    (1, 1001, 'Ayse Kaya', '4242-4242-4242-4242', 'TR330006100519786457841326', 4299.90, 'iyzico', 'captured'),
    (2, 1002, 'Mehmet Demir', '5555-5555-5555-4444', 'TR330006100519786457841326', 1850.00, 'paytr', 'authorized'),
    (3, 1003, 'Elena Rostova', '4000-0566-5566-5556', 'DE89370400440532013000', 649.50, 'stripe', 'captured'),
    (4, 1004, 'Marcus Vance', '4111-1111-1111-1111', 'GB29NWBK60161331926819', 1299.00, 'stripe', 'disputed'),
    (5, 1005, 'Zeynep Yilmaz', '3782-8224-6310-005', 'FR7630006000011234567890189', 920.00, 'iyzico', 'captured')
ON CONFLICT DO NOTHING;

SELECT setval('payments_id_seq', (SELECT COALESCE(MAX(id), 5) FROM payments));

-- Unstructured support ticket text containing embedded PII & leaked secrets (tests content auto-detection!)
INSERT INTO support_tickets (id, customer_id, subject, body, priority, status) VALUES
    (1, 1, 'IBAN refund transfer request', 'Hello, please refund order ORD-2026-1001 to my IBAN TR330006100519786457841326. My TCKN is 10000000146 and email ayse.kaya@example.com.tr.', 'high', 'open'),
    (2, 4, 'API integration error log', 'Our webhook failed while authenticating with key AKIAIOSFODNN7EXAMPLE and card 4242-4242-4242-4242. Contact m.vance@fintech-us.com (SSN 123-45-6789).', 'urgent', 'open'),
    (3, 2, 'Invoice correction', 'Please reissue the invoice for VKN 1234567890 and reach me at +90 533 712 4480.', 'normal', 'pending'),
    (4, 3, 'VAT refund inquiry', 'My EU account is DE89370400440532013000. Can you confirm refund ETA?', 'normal', 'open')
ON CONFLICT DO NOTHING;

SELECT setval('support_tickets_id_seq', (SELECT COALESCE(MAX(id), 4) FROM support_tickets));

-- Restricted table blocked from AI agents and analysts by AST Firewall
INSERT INTO api_secrets (id, service_name, secret_value) VALUES
    (1, 'aws-production-s3', 'AKIAIOSFODNN7EXAMPLE'),
    (2, 'github-deploy-bot', 'ghp_1234567890abcdefghijklmnopqrstuvwxyz'),
    (3, 'openai-enterprise', 'sk-proj-syntheticTestKeyDoNotUseInProduction1234567890')
ON CONFLICT DO NOTHING;
