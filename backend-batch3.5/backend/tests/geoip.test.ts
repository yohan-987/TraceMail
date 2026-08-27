import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyIp } from "../src/utils/ip";
import { createIpApiProvider, createUnavailableGeoIpProvider } from "../src/services/geoipClient";
import { TimeoutError } from "../src/utils/http";
import { publicCandidateIps, analyzeInfrastructure, infrastructureEvidence } from "../src/analyzers/infrastructure";
import { KNOWN_SUSPICIOUS_IPS } from "../src/config/infrastructureSignals";
import type { HeaderAnalysis, IOCSet } from "../src/schemas/types";
import type { DnsProvider } from "../src/services/dnsClient";
import type { GeoIpProvider } from "../src/services/geoipClient";

test("only PUBLIC IPs are GeoIP candidates", () => {
  const headerAnalysis: HeaderAnalysis = {
    emailId: "E",
    anomalies: [],
    receivedChain: [
      {
        hop: 1,
        fromHostname: null,
        fromIp: "10.0.0.1",
        fromIpClassification: "PRIVATE",
        byHostname: null,
        timestampRaw: null,
        timestampIso: null,
        rawHeader: "",
      },
      {
        hop: 2,
        fromHostname: null,
        fromIp: "8.8.8.8",
        fromIpClassification: "PUBLIC",
        byHostname: null,
        timestampRaw: null,
        timestampIso: null,
        rawHeader: "",
      },
    ],
    status: "VERIFIED",
  };
  const iocs: IOCSet = { emailId: "E", ips: ["127.0.0.1", "192.168.1.1"], domains: [], urls: [], hashes: [], emails: [] };
  const ips = publicCandidateIps(headerAnalysis, iocs);
  assert.deepEqual(ips, ["8.8.8.8"]);
  assert.equal(classifyIp("10.0.0.1"), "PRIVATE");
});

test("valid GeoIP response is AVAILABLE with provided fields only", async () => {
  const provider = createIpApiProvider({
    baseUrl: "http://ip-api.example/json",
    fetchImpl: (async () =>
      new Response(
        JSON.stringify({
          status: "success",
          country: "US",
          regionName: "CA",
          city: "Mountain View",
          isp: "Example ISP",
          as: "AS15169",
          org: "Example Org",
        }),
        { status: 200 }
      )) as typeof fetch,
  });
  const result = await provider.lookup("8.8.8.8");
  assert.equal(result.status, "AVAILABLE");
  assert.equal(result.country, "US");
  assert.equal(result.asn, "AS15169");
});

test("GeoIP timeout is ERROR", async () => {
  const provider = createIpApiProvider({
    baseUrl: "http://ip-api.example/json",
    timeoutMs: 20,
    fetchImpl: (async () => {
      throw new TimeoutError();
    }) as typeof fetch,
  });
  const result = await provider.lookup("1.1.1.1");
  assert.equal(result.status, "ERROR");
  assert.equal(result.country, null);
});

test("unavailable GeoIP provider does not invent location", async () => {
  const result = await createUnavailableGeoIpProvider().lookup("1.2.3.4");
  assert.equal(result.status, "UNAVAILABLE");
  assert.equal(result.city, null);
});

test("malformed GeoIP JSON is ERROR", async () => {
  const provider = createIpApiProvider({
    baseUrl: "http://ip-api.example/json",
    fetchImpl: (async () => new Response("not-json", { status: 200 })) as typeof fetch,
  });
  const result = await provider.lookup("1.1.1.1");
  assert.equal(result.status, "ERROR");
});

test("private IPs are never sent to the GeoIP provider", async () => {
  let called = false;
  const geoIp: GeoIpProvider = {
    lookup: async () => {
      called = true;
      return {
        ip: "10.0.0.1",
        country: "XX",
        region: null,
        city: null,
        isp: null,
        asn: null,
        organization: null,
        hosting: null,
        status: "AVAILABLE",
      };
    },
  };
  const dns: DnsProvider = {
    lookup: async (domain) => ({ domain, resolvedIps: null, mxHosts: null, status: "UNAVAILABLE" }),
  };
  const headerAnalysis: HeaderAnalysis = {
    emailId: "E",
    anomalies: [],
    receivedChain: [
      {
        hop: 1,
        fromHostname: null,
        fromIp: "10.0.0.1",
        fromIpClassification: "PRIVATE",
        byHostname: null,
        timestampRaw: null,
        timestampIso: null,
        rawHeader: "",
      },
    ],
    status: "VERIFIED",
  };
  const iocs: IOCSet = { emailId: "E", ips: ["10.0.0.1"], domains: [], urls: [], hashes: [], emails: [] };
  const { infrastructure } = await analyzeInfrastructure({
    emailId: "E",
    headerAnalysis,
    iocs,
    geoIp,
    dns,
  });
  assert.equal(called, false);
  assert.equal(infrastructure.ipIntelligence.length, 0);
  assert.equal(infrastructure.candidateIp, null);
});

test("known suspicious IP emits EXTERNAL_INTELLIGENCE evidence only when listed", () => {
  const ip = "203.0.113.10";
  KNOWN_SUSPICIOUS_IPS.add(ip);
  try {
    const evidence = infrastructureEvidence({ geoRecords: [], publicIps: [ip] });
    assert.ok(evidence.some((e) => e.type === "known_suspicious_infrastructure"));
    assert.ok(evidence.some((e) => e.type === "confirmed_external_intelligence"));
    assert.ok(evidence.every((e) => e.category === "infrastructure"));
  } finally {
    KNOWN_SUSPICIOUS_IPS.delete(ip);
  }
});

test("unlisted IP does not invent suspicious infrastructure", () => {
  const evidence = infrastructureEvidence({
    geoRecords: [
      {
        ip: "8.8.8.8",
        country: "US",
        region: null,
        city: null,
        isp: "Google LLC",
        asn: "AS15169",
        organization: "Google LLC",
        hosting: null,
        status: "AVAILABLE",
      },
    ],
    publicIps: ["8.8.8.8"],
  });
  assert.equal(
    evidence.some((e) => e.type === "known_suspicious_infrastructure" || e.type === "confirmed_external_intelligence"),
    false
  );
});
