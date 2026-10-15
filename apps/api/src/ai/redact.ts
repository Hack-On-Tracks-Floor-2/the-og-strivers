/**
 * AI usage rule: secrets in repository code are never sent to an AI provider.
 * Each secret-looking literal is swapped for a placeholder before the request and
 * swapped back in the response, so search/replace edits still match the real file.
 */
const PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS access key id
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, // GitHub tokens
  /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, // Slack tokens
  /\bsk-[A-Za-z0-9_-]{20,}\b/g, // OpenAI-style keys
  /\bAIza[0-9A-Za-z_-]{35}\b/g, // Google API keys
  /\bgsk_[A-Za-z0-9]{20,}\b/g, // Groq keys
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, // JWTs
  /(?<=[a-z][a-z0-9+.-]*:\/\/[^:/\s"']+:)[^@\s"']{3,}(?=@)/gi, // password inside a connection URL
  // value of password/secret/token/api_key assignments: name = "value"
  /(?<=\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\w*\s*[:=]\s*["'])[^"'\n]{6,}(?=["'])/gi,
];

export interface Redaction {
  text: string;
  count: number;
  restore(output: string): string;
}

export function redactSecrets(input: string): Redaction {
  const secrets = new Map<string, string>(); // value -> placeholder
  let text = input;
  for (const pattern of PATTERNS)
    text = text.replace(pattern, (value) => {
      if (/^«SECRET_\d+»$/.test(value)) return value;
      let placeholder = secrets.get(value);
      if (!placeholder) {
        placeholder = `«SECRET_${secrets.size + 1}»`;
        secrets.set(value, placeholder);
      }
      return placeholder;
    });
  const back = [...secrets.entries()].map(([value, placeholder]) => [placeholder, value] as const);
  return {
    text,
    count: secrets.size,
    restore(output: string) {
      let restored = output;
      for (const [placeholder, value] of back)
        restored = restored.split(placeholder).join(JSON.stringify(value).slice(1, -1));
      return restored;
    },
  };
}
