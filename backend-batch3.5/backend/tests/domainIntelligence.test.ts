import { test } from "node:test";
import assert from "node:assert/strict";
import { enrichDomains, summarizeDomainIntelStatus } from "../src/analyzers/domainIntelligence";
import type { DnsProvider } from "../src/services/dnsClient";

test("valid DNS response is AVAILABLE", async () => {
  const dns: DnsProvider = {
    async lookup(domain) {
      return { domain, resolvedIps: ["93.184.216.34"], mxHosts: ["mail.example.com"], status: "AVAILABLE" };
    },
  };
  const records = await enrichDomains(["Example.COM"], dns);
  assert.equal(records.length, 1);
  assert.equal(records[0].domain, "example.com");
  assert.equal(records[0].status, "AVAILABLE");
  assert.deepEqual(records[0].resolvedIps, ["93.184.216.34"]);
  assert.equal(records[0].registrar, null);
  assert.equal(records[0].domainAgeDays, null);
});

test("missing DNS data is UNAVAILABLE without fabricated records", async () => {
  const dns: DnsProvider = {
    async lookup(domain) {
      return { domain, resolvedIps: null, mxHosts: null, status: "UNAVAILABLE" };
    },
  };
  const records = await enrichDomains(["no-such.invalid"], dns);
  assert.equal(records[0].status, "UNAVAILABLE");
  assert.equal(records[0].resolvedIps, null);
  assert.equal(summarizeDomainIntelStatus(records), "UNAVAILABLE");
});

test("DNS timeout is ERROR", async () => {
  const dns: DnsProvider = {
    async lookup(domain) {
      return { domain, resolvedIps: null, mxHosts: null, status: "ERROR" };
    },
  };
  const records = await enrichDomains(["slow.example"], dns);
  assert.equal(records[0].status, "ERROR");
  assert.equal(summarizeDomainIntelStatus(records), "ERROR");
});

test("empty domain list is NOT_APPLICABLE", () => {
  assert.equal(summarizeDomainIntelStatus([]), "NOT_APPLICABLE");
});
