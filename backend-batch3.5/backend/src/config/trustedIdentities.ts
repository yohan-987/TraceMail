// Deliberately small and hand-curated for the prototype — the spec
// explicitly asks for a "small configurable trusted-brand/person list",
// not a real brand-intelligence database. Extend this list for your
// demo scenarios rather than trying to make it comprehensive.

export interface TrustedBrand {
  name: string;
  domains: string[];
}

export const TRUSTED_BRANDS: TrustedBrand[] = [
  { name: "Google", domains: ["google.com"] },
  { name: "Microsoft", domains: ["microsoft.com"] },
  { name: "PayPal", domains: ["paypal.com"] },
  { name: "Amazon", domains: ["amazon.com"] },
  { name: "Apple", domains: ["apple.com"] },
  { name: "State Bank of India", domains: ["sbi.co.in", "onlinesbi.sbi"] },
];

// Generic authority-implying words in a display name (e.g. "CEO John Smith",
// "IT Support Team") combined with a free/generic webmail sending domain
// is a classic BEC/impersonation pattern even without a specific brand match.
export const AUTHORITY_KEYWORDS = [
  "ceo",
  "chief executive",
  "president",
  "admin",
  "administrator",
  "security team",
  "it support",
  "it department",
  "help desk",
  "finance department",
  "accounts payable",
  "hr department",
  "bank",
];

export const FREE_WEBMAIL_DOMAINS = [
  "gmail.com",
  "yahoo.com",
  "outlook.com",
  "hotmail.com",
  "protonmail.com",
  "aol.com",
  "icloud.com",
];
