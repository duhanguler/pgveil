import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '5s', target: 15 },
    { duration: '15s', target: 30 },
    { duration: '5s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'],
    'http_req_duration{endpoint:inspect}': ['p(95)<25'],
    'http_req_duration{endpoint:playground}': ['p(95)<80'],
  },
};

const BASE = __ENV.PGVEIL_ADMIN_URL || 'http://127.0.0.1:8088';

const payloads = [
  {
    sql: 'SELECT id, full_name, email, tckn, iban FROM customers ORDER BY id LIMIT 8',
    profile: 'ai_agent',
    sample_text: 'Refund IBAN TR330006100519786457841326 TCKN 10000000146 card 4242-4242-4242-4242',
  },
  {
    sql: 'DELETE FROM orders WHERE 1 = 1',
    profile: 'ai_agent',
    sample_text: 'AWS key AKIAIOSFODNN7EXAMPLE leaked by ayse.kaya@example.com.tr',
  },
  {
    sql: "SELECT pg_read_file('/etc/passwd')",
    profile: 'ai_agent',
    sample_text: 'SSN 123-45-6789 EU IBAN DE89370400440532013000',
  },
];

export default function () {
  const sample = payloads[__VU % payloads.length];

  // 1. AST Firewall + Multi-Compliance PII Scan endpoint
  const resInspect = http.post(`${BASE}/api/v1/inspect`, JSON.stringify(sample), {
    headers: { 'Content-Type': 'application/json' },
    tags: { endpoint: 'inspect' },
  });
  check(resInspect, {
    'inspect status 200': (r) => r.status === 200,
    'inspect masked PII': (r) => !r.body.includes('10000000146') && !r.body.includes('AKIAIOSFODNN7EXAMPLE'),
  });

  // 2. Full end-to-end PostgreSQL Wire Proxy execution via Control Plane Playground
  if (__ITER % 3 === 0) {
    const resWire = http.post(
      `${BASE}/api/v1/playground/query`,
      JSON.stringify({
        sql: 'SELECT id, full_name, email, phone, tckn, iban FROM customers ORDER BY id LIMIT 5',
        profile: 'ai_agent',
      }),
      {
        headers: { 'Content-Type': 'application/json' },
        tags: { endpoint: 'playground' },
      }
    );
    check(resWire, {
      'wire status 200': (r) => r.status === 200,
      'wire zero raw TCKN': (r) => !r.body.includes('10000000146'),
      'wire zero raw IBAN': (r) => !r.body.includes('TR330006100519786457841326'),
    });
  }

  sleep(0.02);
}
