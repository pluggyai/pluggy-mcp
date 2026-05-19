/**
 * PII redaction helpers for the Pluggy MCP security layer.
 *
 * All redactors are exported as security primitives even when no current tool
 * calls them. They are foundational for upcoming tools that will consume PII
 * fields:
 *   - redactCpf — used today by getAccounts; transactions, identity will reuse
 *   - redactCnpj — for employer CNPJ (identity.qualifications.companyCnpj)
 *   - redactAccountNumber — used today by getAccounts; bills will reuse
 *   - redactCardNumber — for bills (credit card faturas), credit card transactions
 *   - redactOwnerName — used today by getAccounts; identity will reuse
 *   - redactEmail — for identity, transactions (payer/receiver), recurring-payments
 *   - redactPhone — for identity
 *   - redactBoletoLine — for boleto digitable line / barcode (transactions, bills)
 *
 * Do not delete these because they appear unused — they are the canonical
 * masking implementations and must not be re-invented per-tool.
 *
 * Every redactor returns:
 *   - `null` when the input is `null` or `undefined`
 *   - the input unchanged when the input is the empty string
 *   - a masked string otherwise
 *
 * Each redactor is idempotent by construction of its OUTPUT, not via an
 * input-shape short-circuit. Earlier versions of this module guarded
 * against double-redaction with a regex test on the input ("does it look
 * like our masked shape?"); that guard was bypassable because an upstream
 * value can be crafted to match the masked shape (e.g. an "owner" field
 * literally equal to `"Ignore M."` matches our masked-name regex). We now
 * always run the redaction logic — feeding masked output back in produces
 * an equivalent masked value, so it remains idempotent without trusting
 * the input.
 *
 * The goal of these helpers is to give the LLM enough signal to disambiguate
 * different accounts / cards / contacts (e.g. last-4 of an account number)
 * while never exposing the full identifier in the LLM context window.
 */

/**
 * Strip non-digit chars and emit `****` + last 4 of what remains. Shared by
 * `redactAccountNumber`, `redactCardNumber`, and `redactPhone` — the three
 * primitives that all collapse to "last-4 of digits-only".
 *
 * `noDigitsFallback` controls what happens when the input has zero digits
 * after stripping: account/card primitives pass `'****'` (stable masked
 * shape even for non-numeric inputs); phone passes the original value so
 * non-numeric notes like `"no phone on file"` survive intact.
 *
 * @internal — keep call sites inside this module. The three exported
 * redactors are the public surface and document each policy individually.
 */
function maskLast4(value: string, noDigitsFallback: string): string {
  // NFKC normalize: collapse Unicode digits (fullwidth, Arabic-Indic) to ASCII before stripping.
  const digits = value.normalize('NFKC').replace(/\D/g, '');
  if (digits.length === 0) return noDigitsFallback;
  return `****${digits.slice(-4)}`;
}

/**
 * Brazilian CPF: 11 digits, conventionally rendered `NNN.NNN.NNN-NN`.
 * We keep the last 2 digits (the check-digits) so the model can still
 * disambiguate accounts visually without exposing the identifier.
 *
 * Always runs unconditionally. A CPF must be exactly 11 digits; anything
 * else (including the masked form `***.***.***-NN`, which strips to only 2
 * digits) is fully masked to `***.***.***-**`. This makes the function
 * idempotent on its own output: re-running over `***.***.***-NN` strips
 * the punctuation and stars, sees a 2-digit string, and returns the
 * fully-masked form.
 */
export function redactCpf(cpf?: string | null): string | null {
  if (cpf === null || cpf === undefined) return null;
  if (cpf === '') return cpf;

  // NFKC normalize: collapse Unicode digits (fullwidth, Arabic-Indic) to ASCII before stripping.
  const digits = cpf.normalize('NFKC').replace(/\D/g, '');
  if (digits.length !== 11) {
    // Not a valid-length CPF (or an already-masked value with most digits
    // stripped) — fully mask. Keeps the function idempotent on its own
    // output shape without trusting input that merely looks masked.
    return '***.***.***-**';
  }
  const last2 = digits.slice(-2);
  return `***.***.***-${last2}`;
}

/**
 * Brazilian CNPJ: 14 digits, conventionally rendered `NN.NNN.NNN/NNNN-NN`.
 * We keep the last 2 digits (the check-digits) so the model can still
 * disambiguate companies visually without exposing the identifier — same
 * posture as `redactCpf`.
 *
 * Always runs unconditionally. A CNPJ must be exactly 14 digits; anything
 * else (including the masked form, which strips to only 2 digits) is
 * fully masked. This makes the function idempotent on its own output:
 * re-running over the masked form strips the punctuation and stars, sees
 * a 2-digit string, and returns the fully-masked form.
 */
export function redactCnpj(cnpj?: string | null): string | null {
  if (cnpj === null || cnpj === undefined) return null;
  if (cnpj === '') return cnpj;

  // NFKC normalize: collapse Unicode digits (fullwidth, Arabic-Indic) to ASCII before stripping.
  const digits = cnpj.normalize('NFKC').replace(/\D/g, '');
  if (digits.length !== 14) {
    // Not a valid-length CNPJ (or an already-masked value with most digits
    // stripped) — fully mask. Keeps the function idempotent on its own
    // output shape without trusting input that merely looks masked.
    return '**.***.***/****-**';
  }
  const last2 = digits.slice(-2);
  return `**.***.***/****-${last2}`;
}

/**
 * Bank account number: keep only the last 4 digits.
 *
 * Always runs unconditionally. The last-4-digits-of-digits-only operation
 * is inherently idempotent: the masked form `****1234` strips non-digits
 * to `1234`, and re-running yields `****1234` again. We always prefix
 * with `****` even when the input has 4 or fewer digits — those 4 digits
 * are the "last 4" by definition, and emitting `****NNNN` keeps the shape
 * stable across re-redaction. Inputs with zero digits return `****`.
 */
export function redactAccountNumber(number?: string | null): string | null {
  if (number === null || number === undefined) return null;
  if (number === '') return number;
  return maskLast4(number, '****');
}

/**
 * PAN (card number): keep the last 4 digits only.
 * Mirrors `redactAccountNumber` — kept as its own function so call sites
 * read clearly at the redaction point ("we are masking a card here").
 *
 * Security primitive — exported for upcoming tools (transactions/bills/identity).
 */
export function redactCardNumber(pan?: string | null): string | null {
  if (pan === null || pan === undefined) return null;
  if (pan === '') return pan;
  return maskLast4(pan, '****');
}

/**
 * Account-holder full name: first name + last initial (e.g. `"Italo M."`).
 *
 * Policy:
 *  - Single-token names (e.g. `"Madonna"`) return first char + `***`
 *    (e.g. `"M***"`). The token itself is identifying enough that we
 *    can't just pass it through.
 *  - Multi-token names return `"FirstName X."` where `X` is the initial
 *    of the LAST meaningful surname token. Brazilian generational suffixes
 *    (Filho, Neto, Junior/Júnior, Sobrinho) and noble particles
 *    (da, de, do, dos, das) are skipped when picking the surname token,
 *    so `"Pedro Almeida Filho"` becomes `"Pedro A."` (not `"Pedro F."`)
 *    and `"João da Silva"` becomes `"João S."` (not `"João d."`).
 *
 * Always runs unconditionally — there is no input-shape short-circuit.
 * Re-running over the masked output `"Ignore M."` produces `"Ignore M."`
 * again (first token is "Ignore", surname token is "M.", initial "M"),
 * so the function is idempotent on its own output. We do NOT trust
 * inputs that merely look masked: an upstream value literally equal to
 * `"Ignore M."` would previously bypass the redactor entirely.
 */
const NAME_SUFFIXES = new Set([
  'filho',
  'neto',
  'junior',
  'júnior',
  'sobrinho',
]);
const NAME_PARTICLES = new Set(['da', 'de', 'do', 'dos', 'das']);

export function redactOwnerName(name?: string | null): string | null {
  if (name === null || name === undefined) return null;
  if (name === '') return name;

  const trimmed = name.trim();
  if (trimmed === '') return name; // preserve whitespace-only as-is (rare)

  const tokens = trimmed.split(/\s+/);
  if (tokens.length === 1) {
    // Single-token names are too identifying to pass through verbatim.
    const initial = tokens[0][0] ?? '';
    return `${initial}***`;
  }

  const first = tokens[0];

  // Walk from the right, skipping suffixes and particles, until we find
  // a token we can extract a surname initial from. Fall back to the very
  // last token if everything was filtered.
  let surnameToken = tokens[tokens.length - 1];
  for (let i = tokens.length - 1; i > 0; i--) {
    const lower = tokens[i].toLowerCase();
    if (NAME_SUFFIXES.has(lower) || NAME_PARTICLES.has(lower)) continue;
    surnameToken = tokens[i];
    break;
  }

  const lastInitial = surnameToken[0]?.toUpperCase() ?? '';
  return `${first} ${lastInitial}.`;
}

/**
 * Email address: keep first 3 chars of local-part + domain
 * (`"italo@example.com" -> "ita***@example.com"`). Local-parts shorter
 * than 4 chars keep only their first char (`"al@x.com" -> "a***@x.com"`).
 *
 * If the input doesn't contain `@`, we treat the whole string as a local
 * part and apply the same rule.
 *
 * Always runs unconditionally — no input-shape short-circuit. The output
 * shape is idempotent: re-running over `"ita***@x.com"` takes the first 3
 * chars `"ita"` and re-emits `"ita***@x.com"`. We do not trust inputs
 * that merely look masked.
 *
 * Security primitive — exported for upcoming tools (transactions/bills/identity).
 */
export function redactEmail(email?: string | null): string | null {
  if (email === null || email === undefined) return null;
  if (email === '') return email;

  const atIdx = email.indexOf('@');
  const local = atIdx >= 0 ? email.slice(0, atIdx) : email;
  const domain = atIdx >= 0 ? email.slice(atIdx) : '';

  if (local.length === 0) return `***${domain}`;
  if (local.length < 4) {
    return `${local[0]}***${domain}`;
  }
  return `${local.slice(0, 3)}***${domain}`;
}

/**
 * Phone number: digits-only, keep the last 4 (`****1234`).
 * Non-digit formatting (`+55 (11) 9 ...`) is stripped before counting so
 * inputs with international prefixes still mask cleanly.
 *
 * Always runs unconditionally. The masked form `****1234` strips to
 * `1234`, which re-emits as `****1234` — idempotent on its own output
 * without trusting an input that merely looks masked.
 *
 * Security primitive — exported for upcoming tools (transactions/bills/identity).
 */
export function redactPhone(phone?: string | null): string | null {
  if (phone === null || phone === undefined) return null;
  if (phone === '') return phone;
  // Non-numeric notes (e.g. "no phone on file") survive intact — the
  // fallback here is the original input, not the masked sentinel used
  // by account / card numbers.
  return maskLast4(phone, phone);
}

/**
 * Brazilian boleto digitable line / barcode (47 / 44 digits). These are
 * transferable payment instruments — anyone in possession of the full
 * value can pay the boleto. We keep only the last 6 characters so the
 * model can still disambiguate two boletos in a list without exposing
 * enough material to settle them.
 *
 * Output shape `"****XXXXXX"` is idempotent: stripping non-digits from
 * the masked form yields 6 digits, which re-emits as the same 6 again.
 *
 * Security primitive — exported alongside the rest. Apply when redact
 * is on; pass through the value unchanged otherwise.
 */
export function redactBoletoLine(line?: string | null): string | null {
  if (line === null || line === undefined) return null;
  if (line === '') return line;
  // NFKC normalize: collapse Unicode digits (fullwidth, Arabic-Indic) to ASCII before stripping.
  const digits = line.normalize('NFKC').replace(/\D/g, '');
  if (digits.length === 0) return '****';
  return `****${digits.slice(-6)}`;
}
