import type { SinkRule } from './funnel.js';

/**
 * Detection rules for the languages beyond Python and JavaScript. Every rule carries a CWE, so its
 * OWASP Top 10 category follows from owaspFor(). Memory-safety CWEs (C/C++, unsafe Rust) sit outside
 * the OWASP web Top 10 and are reported with their CWE only.
 */
const r = (id: string, cwe: string, category: string, weight: number, pattern: RegExp): SinkRule => ({ id, cwe, category, weight, pattern });
const SECRET = (prefix: string, assign: string) =>
  r(`${prefix}-secret`, 'CWE-798', 'Hardcoded credential', 4, new RegExp(`(password|passwd|secret|api_?key|token)\\w*\\s*${assign}\\s*["'][^"']{8,}["']`, 'i'));

export const GO_SINKS: SinkRule[] = [
  r('go-sql', 'CWE-89', 'SQL injection', 9, /\.(Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*(ctx,\s*)?(fmt\.Sprintf|"[^"]*"\s*\+)/),
  r('go-sql-build', 'CWE-89', 'SQL injection', 7, /fmt\.Sprintf\s*\(\s*"\s*(SELECT|INSERT|UPDATE|DELETE)\b/i),
  r('go-cmd', 'CWE-78', 'Command injection', 9, /exec\.Command(Context)?\s*\(\s*(ctx,\s*)?("(sh|bash|cmd|\/bin\/sh)"|[a-z]\w*\s*[,)])/),
  r('go-path', 'CWE-22', 'Path traversal', 6, /(os\.(Open|ReadFile|Create|WriteFile|Remove)|ioutil\.ReadFile|http\.ServeFile|filepath\.Join|path\.Join)\s*\([^)]*\b(r\.|name|file|path|filename)\b/i),
  r('go-xss', 'CWE-79', 'Cross-site scripting', 6, /template\.HTML\s*\(|fmt\.Fprintf\s*\(\s*w\s*,\s*"[^"]*<[^"]*%s/),
  r('go-ssrf', 'CWE-918', 'Server-side request forgery', 5, /http\.(Get|Post|Head)\s*\(\s*(r\.|url\b|target|u\b)/),
  r('go-redirect', 'CWE-601', 'Open redirect', 5, /http\.Redirect\s*\([^,]+,[^,]+,\s*r\.(URL\.Query|FormValue)/),
  r('go-gob', 'CWE-502', 'Unsafe deserialization', 6, /gob\.NewDecoder\s*\(\s*r\.Body/),
  r('go-tls', 'CWE-295', 'TLS verification disabled', 5, /InsecureSkipVerify\s*:\s*true/),
  r('go-weak-hash', 'CWE-328', 'Weak hashing', 3, /\b(md5|sha1)\.(New|Sum)\s*\(/),
  r('go-cipher', 'CWE-327', 'Broken cipher', 5, /\b(des|rc4)\.New\w*\s*\(/),
  r('go-rand', 'CWE-338', 'Insecure randomness', 3, /\brand\.(Intn|Int63|Int|Read)\s*\(.*(token|secret|key|password)/i),
  r('go-jwt', 'CWE-347', 'JWT signature not verified', 6, /SigningMethodNone|UnsafeAllowNoneSignatureType|ParseUnverified\s*\(/),
  r('go-cookie', 'CWE-614', 'Insecure cookie', 3, /\b(Secure|HttpOnly)\s*:\s*false/),
  r('go-cors', 'CWE-942', 'Permissive CORS', 3, /Access-Control-Allow-Origin"\s*,\s*"\*"/),
  r('go-mass-assign', 'CWE-915', 'Mass assignment', 3, /\.(Bind|ShouldBind|ShouldBindJSON|BindJSON)\s*\(\s*&\w+\s*\).*\bUpdate|db\.(Save|Updates)\s*\(\s*&?input\b/),
  r('go-log-secret', 'CWE-532', 'Secret written to logs', 3, /log\.(Print|Printf|Println|Fatal\w*)\s*\([^)]*\b(password|secret|token)\b/i),
  r('go-swallowed-error', 'CWE-390', 'Exception silently swallowed', 2, /if\s+err\s*!=\s*nil\s*\{\s*\}/),
  r('go-debug', 'CWE-489', 'Debug mode enabled', 2, /gin\.SetMode\s*\(\s*gin\.DebugMode\s*\)|pprof/),
  SECRET('go', ':?='),
];

const JVM_SINKS = (p: string): SinkRule[] => [
  r(`${p}-sql`, 'CWE-89', 'SQL injection', 9, /(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery)\s*\(\s*("[^"]*"\s*\+|[a-z]\w*\s*\+|String\.format|"[^"]*\$\{?\w)/),
  r(`${p}-sql-build`, 'CWE-89', 'SQL injection', 7, /"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+|"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*\$\{?\w/i),
  r(`${p}-cmd`, 'CWE-78', 'Command injection', 9, /Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(\s*("(sh|bash|cmd)"|[^)]*\+)/),
  r(`${p}-path`, 'CWE-22', 'Path traversal', 6, /(new\s+File(InputStream|Reader|OutputStream)?|File|Paths\.get|Path\.of)\s*\([^)]*(getParameter|\bname\b|\bfile\w*|\bpath\b)/i),
  r(`${p}-deserialize`, 'CWE-502', 'Unsafe deserialization', 8, /new\s+ObjectInputStream\s*\(|XMLDecoder\s*\(|enableDefaultTyping|activateDefaultTyping|new\s+Yaml\s*\(\s*\)\.load/),
  r(`${p}-xxe`, 'CWE-611', 'XML external entities', 4, /(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\.newInstance\s*\(/),
  r(`${p}-xss`, 'CWE-79', 'Cross-site scripting', 6, /getWriter\(\)\.(print|println|write)\s*\([^)]*(getParameter|\+)/),
  r(`${p}-spel`, 'CWE-94', 'Expression language injection', 7, /parseExpression\s*\(|ScriptEngineManager\(\)/),
  r(`${p}-ldap`, 'CWE-90', 'LDAP/XPath injection', 6, /\.(search|evaluate|compile)\s*\([^)]*"\s*\+/),
  r(`${p}-ssrf`, 'CWE-918', 'Server-side request forgery', 5, /(new\s+URL\s*\([^)]*(getParameter|url)\b|getForObject\s*\(\s*(url|request))/),
  r(`${p}-redirect`, 'CWE-601', 'Open redirect', 5, /sendRedirect\s*\([^)]*getParameter|"redirect:"\s*\+/),
  r(`${p}-weak-hash`, 'CWE-328', 'Weak hashing', 3, /MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-?1)"/i),
  r(`${p}-cipher`, 'CWE-327', 'Broken cipher', 5, /Cipher\.getInstance\s*\(\s*"(DES|DESede|RC4|Blowfish|[^"]*\/ECB\/)/i),
  r(`${p}-random`, 'CWE-338', 'Insecure randomness', 3, /(new\s+Random\s*\(|Math\.random\s*\().*(token|secret|password|key)/i),
  r(`${p}-tls`, 'CWE-295', 'TLS verification disabled', 5, /ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|setHostnameVerifier\s*\([^)]*->\s*true|X509TrustManager/),
  r(`${p}-jwt`, 'CWE-347', 'JWT signature not verified', 6, /parseClaimsJwt|parseUnsecuredClaims|Algorithm\.none\(\)/),
  r(`${p}-cookie`, 'CWE-614', 'Insecure cookie', 3, /setSecure\s*\(\s*false\s*\)|setHttpOnly\s*\(\s*false\s*\)/),
  r(`${p}-cors`, 'CWE-942', 'Permissive CORS', 3, /allowedOrigins\s*\(\s*"\*"\s*\)|@CrossOrigin\s*\(\s*(origins\s*=\s*)?"\*"/),
  r(`${p}-mass-assign`, 'CWE-915', 'Mass assignment', 3, /BeanUtils\.copyProperties\s*\(\s*request|@ModelAttribute\s+\w+Entity/),
  r(`${p}-log-secret`, 'CWE-532', 'Secret written to logs', 3, /(log|logger|LOG|LOGGER)\.(info|debug|warn|error|trace)\s*\([^)]*\b(password|secret|token)\b/i),
  r(`${p}-swallowed-error`, 'CWE-390', 'Exception silently swallowed', 2, /catch\s*\([^)]*\)\s*\{\s*\}/),
  SECRET(p, '='),
];
export const JAVA_SINKS = JVM_SINKS('java');
export const KOTLIN_SINKS = JVM_SINKS('kt');

export const CSHARP_SINKS: SinkRule[] = [
  r('cs-sql', 'CWE-89', 'SQL injection', 9, /(new\s+SqlCommand|ExecuteSqlRaw|FromSqlRaw|ExecuteSqlCommand|SqlQuery)\s*\(\s*(\$"|"[^"]*"\s*\+|string\.Format)/),
  r('cs-cmd', 'CWE-78', 'Command injection', 7, /Process\.Start\s*\(|new\s+ProcessStartInfo\s*\(/),
  r('cs-path', 'CWE-22', 'Path traversal', 6, /(File\.(ReadAllText|ReadAllBytes|Open|OpenRead|WriteAllText|Delete)|Path\.Combine|PhysicalFile)\s*\([^)]*(Request|\bname\b|\bfile\w*|\bpath\b)/i),
  r('cs-deserialize', 'CWE-502', 'Unsafe deserialization', 8, /BinaryFormatter|TypeNameHandling\.(All|Auto|Objects)|LosFormatter|NetDataContractSerializer|SoapFormatter/),
  r('cs-xxe', 'CWE-611', 'XML external entities', 6, /DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver/),
  r('cs-xss', 'CWE-79', 'Cross-site scripting', 6, /Html\.Raw\s*\(|new\s+HtmlString\s*\(/),
  r('cs-redirect', 'CWE-601', 'Open redirect', 5, /\bRedirect\s*\(\s*(returnUrl|url|Request\.)/),
  r('cs-ssrf', 'CWE-918', 'Server-side request forgery', 5, /\.(GetAsync|GetStringAsync|DownloadString|DownloadStringTaskAsync)\s*\(\s*(url|Request|target)\b/),
  r('cs-weak-hash', 'CWE-328', 'Weak hashing', 3, /\b(MD5|SHA1)\.Create\s*\(|new\s+(MD5|SHA1)CryptoServiceProvider/),
  r('cs-cipher', 'CWE-327', 'Broken cipher', 5, /\b(DES|TripleDES|RC2)\.Create\s*\(|CipherMode\.ECB/),
  r('cs-random', 'CWE-338', 'Insecure randomness', 3, /new\s+Random\s*\(.*(token|secret|password|key)/i),
  r('cs-tls', 'CWE-295', 'TLS verification disabled', 5, /ServerCertificate(Custom)?ValidationCallback\s*=.*=>\s*true/),
  r('cs-jwt', 'CWE-347', 'JWT signature not verified', 6, /(ValidateIssuerSigningKey|RequireSignedTokens|ValidateLifetime)\s*=\s*false/),
  r('cs-cookie', 'CWE-614', 'Insecure cookie', 3, /\b(Secure|HttpOnly)\s*=\s*false/),
  r('cs-cors', 'CWE-942', 'Permissive CORS', 3, /AllowAnyOrigin\s*\(\s*\)/),
  r('cs-mass-assign', 'CWE-915', 'Mass assignment', 3, /TryUpdateModelAsync\s*\(|\[Bind\(\s*\)\]/),
  r('cs-log-secret', 'CWE-532', 'Secret written to logs', 3, /\.Log(Information|Debug|Warning|Error|Trace)\s*\([^)]*\b(password|secret|token)\b/i),
  r('cs-swallowed-error', 'CWE-390', 'Exception silently swallowed', 2, /catch\s*(\([^)]*\))?\s*\{\s*\}/),
  r('cs-debug', 'CWE-489', 'Debug mode enabled', 2, /UseDeveloperExceptionPage\s*\(/),
  SECRET('cs', '='),
];

export const PHP_SINKS: SinkRule[] = [
  r('php-sql', 'CWE-89', 'SQL injection', 9, /(mysqli_query|mysql_query|pg_query|->query|->exec|->prepare)\s*\([^)]*(\$_(GET|POST|REQUEST|COOKIE)|"[^"]*\$\w+|['"]\s*\.\s*\$)/i),
  r('php-sql-build', 'CWE-89', 'SQL injection', 7, /["']\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"']*(["']\s*\.\s*\$|\$\w+)/i),
  r('php-cmd', 'CWE-78', 'Command injection', 9, /\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(|`[^`]*\$\w+/),
  r('php-eval', 'CWE-95', 'Code injection', 9, /\b(eval|assert|create_function)\s*\(|preg_replace\s*\(\s*['"][^'"]*\/e[a-z]*['"]/),
  r('php-include', 'CWE-98', 'File inclusion', 8, /\b(include|require)(_once)?\s*\(?\s*\$/),
  r('php-path', 'CWE-22', 'Path traversal', 6, /\b(file_get_contents|fopen|readfile|unlink|file_put_contents|file)\s*\([^)]*\$/),
  r('php-xss', 'CWE-79', 'Cross-site scripting', 6, /\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)|<\?=\s*\$_(GET|POST|REQUEST)/),
  r('php-deserialize', 'CWE-502', 'Unsafe deserialization', 8, /\bunserialize\s*\(/),
  r('php-redirect', 'CWE-601', 'Open redirect', 5, /header\s*\(\s*["']Location:[^"']*["']\s*\.\s*\$_(GET|REQUEST)/i),
  r('php-ssrf', 'CWE-918', 'Server-side request forgery', 5, /(file_get_contents|curl_init|fopen)\s*\(\s*\$_(GET|POST|REQUEST)/),
  r('php-xxe', 'CWE-611', 'XML external entities', 6, /LIBXML_NOENT|libxml_disable_entity_loader\s*\(\s*false/),
  r('php-password-hash', 'CWE-916', 'Weak password hashing', 5, /\b(md5|sha1)\s*\(\s*\$\w*pass/i),
  r('php-weak-hash', 'CWE-328', 'Weak hashing', 3, /\b(md5|sha1)\s*\(/),
  r('php-random', 'CWE-338', 'Insecure randomness', 3, /\b(rand|mt_rand|uniqid)\s*\(.*(token|secret|key|password)/i),
  r('php-tls', 'CWE-295', 'TLS verification disabled', 5, /CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)/),
  r('php-jwt', 'CWE-347', 'JWT signature not verified', 6, /['"]alg['"]\s*=>\s*['"]none['"]|JWT::decode\s*\([^,)]*\)/),
  r('php-cookie', 'CWE-614', 'Insecure cookie', 3, /setcookie\s*\([^)]*,\s*false\s*,\s*false\s*\)|['"](secure|httponly)['"]\s*=>\s*false/i),
  r('php-cors', 'CWE-942', 'Permissive CORS', 3, /Access-Control-Allow-Origin:\s*\*/),
  r('php-mass-assign', 'CWE-915', 'Mass assignment', 4, /->(fill|update|create|forceFill)\s*\(\s*\$request->all\(\)\s*\)|\$guarded\s*=\s*\[\s*\]/),
  r('php-log-secret', 'CWE-532', 'Secret written to logs', 3, /(error_log|Log::\w+|->(info|debug|error|warning))\s*\([^)]*\b(password|secret|token)\b/i),
  r('php-swallowed-error', 'CWE-390', 'Exception silently swallowed', 2, /catch\s*\([^)]*\)\s*\{\s*\}/),
  r('php-debug', 'CWE-489', 'Debug mode enabled', 2, /display_errors['"]?\s*,\s*['"]?(1|On|true)|APP_DEBUG\s*=\s*true/i),
  SECRET('php', '='),
];

export const RUBY_SINKS: SinkRule[] = [
  // Ruby interpolates #{} only inside double quotes (which may contain single quotes, e.g. SQL literals).
  r('rb-sql', 'CWE-89', 'SQL injection', 9, /(\.|\b)(where|find_by_sql|exec_query|execute|order|joins|group|having|pluck|count_by_sql)\s*\(?\s*"[^"]*#\{|\.select\s*\(\s*"[^"]*#\{/),
  r('rb-sql-concat', 'CWE-89', 'SQL injection', 7, /["']\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*\+|"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*#\{/i),
  r('rb-cmd', 'CWE-78', 'Command injection', 9, /\b(system|exec|spawn|IO\.popen|Open3\.\w+)\s*\(?\s*"[^"]*#\{|`[^`]*#\{|%x\{[^}]*#\{/),
  r('rb-eval', 'CWE-95', 'Code injection', 9, /\b(eval|instance_eval|class_eval|module_eval)\s*\(|\.(send|public_send|constantize)\s*\(\s*params/),
  r('rb-path', 'CWE-22', 'Path traversal', 6, /(File\.(read|open|new|write|delete)|IO\.read|send_file|File\.join)\s*\(?[^)\n]*\b(params|name|file\w*|path)\b/),
  r('rb-deserialize', 'CWE-502', 'Unsafe deserialization', 8, /Marshal\.load|YAML\.load(?!_file)\b|YAML\.unsafe_load|Oj\.load\s*\(/),
  r('rb-xss', 'CWE-79', 'Cross-site scripting', 6, /\.html_safe\b|\braw\s*\(|<%==/),
  r('rb-redirect', 'CWE-601', 'Open redirect', 5, /redirect_to\s*\(?\s*params/),
  r('rb-ssrf', 'CWE-918', 'Server-side request forgery', 5, /(Net::HTTP\.get|URI\.open|HTTParty\.get|Faraday\.get|open)\s*\(\s*(params|url\b)/),
  r('rb-mass-assign', 'CWE-915', 'Mass assignment', 5, /\.permit!|\.(new|create|update|update_attributes)\s*\(\s*params\[:\w+\]\s*\)/),
  r('rb-weak-hash', 'CWE-328', 'Weak hashing', 3, /Digest::(MD5|SHA1)/),
  r('rb-random', 'CWE-338', 'Insecure randomness', 3, /\brand\s*\(.*(token|secret|key|password)/i),
  r('rb-tls', 'CWE-295', 'TLS verification disabled', 5, /VERIFY_NONE|ssl_verify:\s*false|verify_ssl:\s*false/),
  r('rb-jwt', 'CWE-347', 'JWT signature not verified', 6, /JWT\.decode\s*\([^)]*,\s*(nil|false)\b/),
  r('rb-cookie', 'CWE-614', 'Insecure cookie', 3, /\b(secure|httponly):\s*false/),
  r('rb-cors', 'CWE-942', 'Permissive CORS', 3, /origins\s+['"]\*['"]/),
  r('rb-xxe', 'CWE-611', 'XML external entities', 6, /Nokogiri::XML.*(NOENT|noent)/),
  r('rb-log-secret', 'CWE-532', 'Secret written to logs', 3, /(logger|Rails\.logger)\.(info|debug|warn|error)\s*\(?[^)\n]*\b(password|secret|token)\b/i),
  r('rb-swallowed-error', 'CWE-390', 'Exception silently swallowed', 2, /rescue(\s+\w+)?(\s*=>\s*\w+)?\s*(;\s*)?nil\b/),
  r('rb-debug', 'CWE-489', 'Debug mode enabled', 2, /consider_all_requests_local\s*=\s*true/),
  SECRET('rb', '='),
];

export const C_SINKS: SinkRule[] = [
  r('c-cmd', 'CWE-78', 'Command injection', 9, /\b(system|popen|execl|execlp|execle|execv|execvp)\s*\(/),
  r('c-sql', 'CWE-89', 'SQL injection', 8, /sprintf\s*\([^,]+,\s*"\s*(SELECT|INSERT|UPDATE|DELETE)\b|sqlite3_exec\s*\([^,]+,\s*[a-z_]\w*/i),
  r('c-overflow', 'CWE-120', 'Buffer overflow', 8, /\b(strcpy|strcat|sprintf|vsprintf|gets|scanf)\s*\(/),
  r('c-format', 'CWE-134', 'Format string', 7, /\b(printf|fprintf\s*\(\s*\w+\s*,|syslog\s*\(\s*\w+\s*,)\s*\(?\s*[a-z_]\w*\s*\)/),
  r('c-path', 'CWE-22', 'Path traversal', 4, /\bfopen\s*\(\s*[a-z_]\w*\s*,/),
  r('c-rand', 'CWE-338', 'Insecure randomness', 3, /\brand\s*\(\s*\)|srand\s*\(\s*time/),
  r('c-weak-hash', 'CWE-328', 'Weak hashing', 3, /\b(MD5_Init|SHA1_Init|EVP_md5|EVP_sha1)\b/),
  r('c-cipher', 'CWE-327', 'Broken cipher', 5, /\bEVP_(des_|rc4)|_ecb\s*\(/),
  r('c-tls', 'CWE-295', 'TLS verification disabled', 5, /SSL_VERIFY_NONE/),
  r('c-log-secret', 'CWE-532', 'Secret written to logs', 3, /(printf|fprintf|syslog)\s*\([^)]*\b(password|secret|token)\b/i),
  SECRET('c', '(\\[\\])?\\s*='),
];

export const RUST_SINKS: SinkRule[] = [
  r('rs-sql', 'CWE-89', 'SQL injection', 9, /\b(query|execute|query_as|query_scalar)\s*(::<[^>]*>)?\s*\(\s*&?format!\s*\(/),
  r('rs-sql-build', 'CWE-89', 'SQL injection', 7, /format!\s*\(\s*"\s*(SELECT|INSERT|UPDATE|DELETE)\b/i),
  r('rs-cmd', 'CWE-78', 'Command injection', 8, /Command::new\s*\(\s*("(sh|bash|cmd)"|[a-z_]\w*\s*\))/),
  r('rs-path', 'CWE-22', 'Path traversal', 6, /(File::open|File::create|fs::read_to_string|fs::read|fs::write|fs::remove_file)\s*\([^)]*\b(name|path|file\w*|req|query)\b/),
  r('rs-unsafe', 'CWE-119', 'Unsafe memory access', 4, /\bunsafe\s*\{/),
  r('rs-ssrf', 'CWE-918', 'Server-side request forgery', 5, /reqwest::(blocking::)?get\s*\(\s*&?(url|target|req)\b/),
  r('rs-tls', 'CWE-295', 'TLS verification disabled', 5, /danger_accept_invalid_certs\s*\(\s*true\s*\)|SslVerifyMode::NONE/),
  r('rs-weak-hash', 'CWE-328', 'Weak hashing', 3, /\b(Md5|Sha1)::new\s*\(|md5::compute/),
  r('rs-deserialize', 'CWE-502', 'Unsafe deserialization', 5, /bincode::deserialize\s*\(\s*&?(body|req|input)/),
  r('rs-log-secret', 'CWE-532', 'Secret written to logs', 3, /(info!|debug!|warn!|error!|println!)\s*\([^)]*\b(password|secret|token)\b/i),
  r('rs-swallowed-error', 'CWE-390', 'Exception silently swallowed', 2, /Err\(_\)\s*=>\s*\{\s*\}|let\s+_\s*=\s*[^;]+\?;/),
  SECRET('rs', '(:\\s*&\\w+)?\\s*='),
];

export const USER_INPUT: Record<string, RegExp> = {
  go: /\br\.(URL\.Query|FormValue|PostFormValue|Form|Body|Header)|\bc\.(Param|Query|PostForm|ShouldBind)|mux\.Vars/,
  java: /request\.get(Parameter|Header|QueryString|InputStream|Reader)|@RequestParam|@PathVariable|@RequestBody/,
  kotlin: /request\.get(Parameter|Header|QueryString)|@RequestParam|@PathVariable|@RequestBody|call\.(parameters|receive)/,
  csharp: /Request\.(Query|Form|Body|Headers|Cookies)|\[From(Query|Body|Route|Form)\]/,
  php: /\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)|\$request->(input|get|query|all)/,
  ruby: /\bparams\[|\bparams\.(require|permit)|request\.(params|body|headers)/,
  c: /\bargv\[|getenv\s*\(|recv\s*\(|fgets\s*\(|\bscanf\s*\(/,
  rust: /web::(Query|Path|Json|Form)|req\.(query|param|match_info)|std::env::args|Query<|Json</,
};
export const ROUTE: Record<string, RegExp> = {
  go: /\bfunc\s+\w*\s*\(\s*w\s+http\.ResponseWriter|\.(GET|POST|HandleFunc)\s*\(/,
  java: /@(Get|Post|Put|Delete|Request)Mapping|@WebServlet|doGet|doPost/,
  kotlin: /@(Get|Post|Put|Delete|Request)Mapping|routing\s*\{|\b(get|post)\s*\(\s*"/,
  csharp: /\[Http(Get|Post|Put|Delete)\]|\bMap(Get|Post)\s*\(/,
  php: /Route::(get|post|put|delete)|function\s+\w+Action\s*\(/,
  ruby: /\b(get|post|put|delete)\s+['"]\/|def\s+(index|show|create|update|destroy)\b/,
  c: /\bmain\s*\(/,
  rust: /#\[(get|post|put|delete)\(|\.route\s*\(/,
};

/** Line that opens a function body, per language family (used to cut out the enclosing function). */
export const SIGNATURE: Record<string, RegExp> = {
  go: /^\s*func\b/,
  rust: /^\s*(pub(\([^)]*\))?\s+)?(async\s+)?(unsafe\s+)?(const\s+)?(extern\s+"[^"]*"\s+)?fn\s+\w+/,
  kotlin: /^\s*((public|private|protected|internal|override|open|suspend|inline|operator|abstract)\s+)*fun\s+/,
  php: /^\s*((public|private|protected|static|final|abstract)\s+)*function\s+&?\w*\s*\(/,
  // Java, C#, C and C++: "<modifiers/type> name(...)" not ending in ';' and not a control statement.
  java: /^\s*(?!(if|for|foreach|while|switch|catch|else|return|new|throw|do|try|using|lock|sizeof|case|synchronized)\b)[\w<>[\],.?*&:~@\s]+?\s+[*&]?[\w:~]+\s*\([^;]*$/,
  ruby: /^\s*def\s+/,
};
