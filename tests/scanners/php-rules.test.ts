import { describe, expect, it } from 'vitest';
import { PHP_SINKS } from '../../apps/api/src/scanners/languages';

const matches = (line: string) => PHP_SINKS.filter((rule) => rule.pattern.test(line)).map((rule) => rule.id);

describe('PHP scanner rules', () => {
  it('detects SQL concatenated after a quoted value', () => {
    expect(matches(`$sql = "SELECT * FROM patients WHERE doctor = '" . $doctor . "'";`)).toContain('php-sql-build');
  });
  it('still detects shell execution functions', () => {
    expect(matches("return shell_exec('wc -w < ' . $file);")).toContain('php-cmd');
    expect(matches('exec($command);')).toContain('php-cmd');
  });
  it('does not treat PDO::exec as command execution', () => {
    expect(matches("$db->exec('CREATE TABLE patients (id INTEGER PRIMARY KEY)');")).not.toContain('php-cmd');
  });
});
