/**
 * OWASP A06 (Vulnerable and Outdated Components): the sandbox's preparation stage runs `npm audit`
 * or `pip-audit` against the installed dependencies and writes JSON; this turns it into advisories.
 */
export interface Advisory {
  name: string;
  version: string;
  severity: string;
  ids: string[];
  fix: string | null;
}

export function parseAudit(runtime: string, text: string | undefined): Advisory[] | null {
  if (!text?.trim()) return null;
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return null;
  }
  if (runtime === 'php') {
    // composer audit --format=json: { advisories: { "vendor/pkg": [{ advisoryId, cve, title, affectedVersions }] } }
    const advisories = (json as { advisories?: Record<string, { advisoryId?: string; cve?: string | null; affectedVersions?: string }[]> }).advisories ?? {};
    return Object.entries(Array.isArray(advisories) ? {} : advisories).map(([name, list]) => ({
      name,
      version: list[0]?.affectedVersions ?? '',
      severity: 'known CVE',
      ids: list.flatMap((v) => [v.cve, v.advisoryId].filter((x): x is string => !!x)).slice(0, 5),
      fix: 'composer update',
    }));
  }
  if (runtime === 'node' || runtime === 'javascript') {
    // npm 7+: { vulnerabilities: { name: { severity, range, via: [..], fixAvailable } } }
    const vulns = (json as { vulnerabilities?: Record<string, { severity?: string; range?: string; via?: unknown[]; fixAvailable?: unknown }> }).vulnerabilities ?? {};
    return Object.entries(vulns).map(([name, v]) => ({
      name,
      version: v.range ?? '',
      severity: v.severity ?? 'unknown',
      ids: (v.via ?? [])
        .map((x) => (typeof x === 'object' && x && 'url' in x ? String((x as { url: string }).url).split('/').pop()! : null))
        .filter((x): x is string => !!x)
        .slice(0, 5),
      fix: v.fixAvailable ? (typeof v.fixAvailable === 'object' ? `upgrade to ${(v.fixAvailable as { version?: string }).version ?? 'a fixed version'}` : 'npm audit fix') : null,
    }));
  }
  if (runtime !== 'python') return null;
  // pip-audit -f json: { dependencies: [{ name, version, vulns: [{ id, fix_versions, aliases }] }] } (older: a bare list)
  const deps = Array.isArray(json) ? json : ((json as { dependencies?: unknown[] }).dependencies ?? []);
  return (deps as { name: string; version: string; vulns?: { id: string; fix_versions?: string[]; aliases?: string[] }[] }[])
    .filter((d) => d.vulns?.length)
    .map((d) => ({
      name: d.name,
      version: d.version,
      severity: 'known CVE',
      ids: d.vulns!.flatMap((v) => [v.id, ...(v.aliases ?? [])]).slice(0, 5),
      fix: d.vulns!.flatMap((v) => v.fix_versions ?? []).sort().pop() ? `upgrade to ${d.vulns!.flatMap((v) => v.fix_versions ?? []).sort().pop()}` : null,
    }));
}

export function auditSummary(advisories: Advisory[]) {
  if (!advisories.length) return 'Dependency audit (OWASP A06): no known-vulnerable packages.';
  const list = advisories
    .slice(0, 8)
    .map((a) => `${a.name}${a.version ? ` ${a.version}` : ''} (${a.severity}${a.ids.length ? `, ${a.ids.slice(0, 2).join('/')}` : ''}${a.fix ? `; ${a.fix}` : ''})`)
    .join('; ');
  return `Dependency audit (OWASP A06): ${advisories.length} vulnerable package${advisories.length > 1 ? 's' : ''} — ${list}${advisories.length > 8 ? '; …' : ''}.`;
}
