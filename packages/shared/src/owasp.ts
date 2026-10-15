/** OWASP Top 10 (2021) categories and the CWEs ProofPatch maps to each. Shared by the API and the web app. */
export const OWASP_TOP_10 = [
  { id: 'A01', name: 'Broken Access Control', cwes: ['CWE-22', 'CWE-23', 'CWE-35', 'CWE-59', 'CWE-200', 'CWE-284', 'CWE-285', 'CWE-352', 'CWE-377', 'CWE-601', 'CWE-639', 'CWE-942'] },
  { id: 'A02', name: 'Cryptographic Failures', cwes: ['CWE-259', 'CWE-261', 'CWE-295', 'CWE-319', 'CWE-326', 'CWE-327', 'CWE-328', 'CWE-330', 'CWE-338', 'CWE-916'] },
  { id: 'A03', name: 'Injection', cwes: ['CWE-20', 'CWE-74', 'CWE-77', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-90', 'CWE-94', 'CWE-95', 'CWE-643', 'CWE-943', 'CWE-1336'] },
  { id: 'A04', name: 'Insecure Design', cwes: ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522', 'CWE-915', 'CWE-1321'] },
  { id: 'A05', name: 'Security Misconfiguration', cwes: ['CWE-16', 'CWE-489', 'CWE-611', 'CWE-614', 'CWE-1004', 'CWE-1333'] },
  { id: 'A06', name: 'Vulnerable and Outdated Components', cwes: ['CWE-1035', 'CWE-1104'] },
  { id: 'A07', name: 'Identification and Authentication Failures', cwes: ['CWE-287', 'CWE-306', 'CWE-347', 'CWE-384', 'CWE-521', 'CWE-798'] },
  { id: 'A08', name: 'Software and Data Integrity Failures', cwes: ['CWE-345', 'CWE-494', 'CWE-502', 'CWE-829'] },
  { id: 'A09', name: 'Security Logging and Monitoring Failures', cwes: ['CWE-117', 'CWE-223', 'CWE-390', 'CWE-532', 'CWE-778'] },
  { id: 'A10', name: 'Server-Side Request Forgery', cwes: ['CWE-918'] },
] as const;
export type OwaspCategory = (typeof OWASP_TOP_10)[number];

/** OWASP Top 10 category for a CWE id like "CWE-89", or null when it is outside the Top 10 mapping. */
export function owaspFor(cwe: string | null | undefined): OwaspCategory | null {
  if (!cwe) return null;
  return OWASP_TOP_10.find((c) => (c.cwes as readonly string[]).includes(cwe)) ?? null;
}
