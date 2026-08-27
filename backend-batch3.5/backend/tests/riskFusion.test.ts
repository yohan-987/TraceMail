import { test } from "node:test";
import assert from "node:assert/strict";
import { computeRisk } from "../src/analyzers/riskEngine";
import type { RiskEvidenceItem } from "../src/schemas/types";

function item(overrides: Partial<RiskEvidenceItem>): RiskEvidenceItem {
  return {
    type: "t",
    severity: "medium",
    weight: 20,
    message: "m",
    evidence: {},
    category: "content",
    provenance: "DETERMINISTIC_ANALYSIS",
    ...overrides,
  };
}

const base = {
  headerDataAvailable: true,
  urlDomainApplicable: true,
  infrastructureAvailable: false,
};

test("ML content evidence fuses with deterministic content via noisy-OR, not a second scoring system", () => {
  const det = item({ type: "urgency_language", weight: 15, provenance: "DETERMINISTIC_ANALYSIS" });
  const ml = item({
    type: "ml_phishing_classification",
    weight: 35,
    provenance: "ML_ASSESSMENT",
  });
  const fused = computeRisk("EMAIL-F1", [det, ml], base);
  const onlyDet = computeRisk("EMAIL-F1b", [det], base);
  assert.equal(fused.categoryScores?.content.status, "AVAILABLE");
  assert.ok((fused.categoryScores?.content.score ?? 0) > (onlyDet.categoryScores?.content.score ?? 0));
  assert.ok((fused.categoryScores?.content.score ?? 0) < 15 + 35);
  assert.ok((fused.score ?? 0) >= 0 && (fused.score ?? 0) <= 100);
  assert.equal(fused.categoryScores?.content.evidence.some((e) => e.provenance === "ML_ASSESSMENT"), true);
  assert.equal(fused.categoryScores?.content.evidence.some((e) => e.provenance === "DETERMINISTIC_ANALYSIS"), true);
});

test("infrastructure enrichment is AVAILABLE with score when status override is AVAILABLE", () => {
  const infra = item({
    type: "cloud_vps_indicator",
    category: "infrastructure",
    weight: 15,
    provenance: "INFERRED",
  });
  const risk = computeRisk("EMAIL-F2", [infra], {
    ...base,
    infrastructureAvailable: true,
    infrastructureStatus: "AVAILABLE",
  });
  assert.equal(risk.categoryScores?.infrastructure.status, "AVAILABLE");
  assert.equal(risk.categoryScores?.infrastructure.score, 15);
  assert.equal(risk.evidenceCoverage, 1);
});

test("missing intelligence stays UNAVAILABLE with null score, not zero", () => {
  const risk = computeRisk("EMAIL-F3", [], {
    ...base,
    infrastructureAvailable: false,
    infrastructureStatus: "UNAVAILABLE",
  });
  assert.equal(risk.categoryScores?.infrastructure.status, "UNAVAILABLE");
  assert.equal(risk.categoryScores?.infrastructure.score, null);
  assert.equal(risk.evidenceCoverage, 0.8);
});

test("ERROR infrastructure is excluded from the fused score", () => {
  const risk = computeRisk(
    "EMAIL-F4",
    [item({ category: "technical", weight: 100 })],
    { ...base, infrastructureStatus: "ERROR" }
  );
  assert.equal(risk.categoryScores?.infrastructure.status, "ERROR");
  assert.equal(risk.categoryScores?.infrastructure.score, null);
  assert.equal(risk.score, 29);
});

test("correlated SPF/DKIM/DMARC remain non-additive after Batch 4 fusion", () => {
  const evidence = [
    item({ type: "spf_fail", category: "technical", weight: 25 }),
    item({ type: "dkim_fail", category: "technical", weight: 25 }),
    item({ type: "dmarc_fail", category: "technical", weight: 30 }),
  ];
  const risk = computeRisk("EMAIL-F5", evidence, base);
  assert.equal(risk.categoryScores?.technical.score, 61);
  assert.ok((risk.categoryScores?.technical.score ?? 0) < 80);
});

test("infrastructure category score is capped at 100 via noisy-OR", () => {
  const evidence = [
    item({ category: "infrastructure", weight: 40, type: "confirmed_external_intelligence" }),
    item({ category: "infrastructure", weight: 30, type: "known_suspicious_infrastructure" }),
    item({ category: "infrastructure", weight: 20, type: "suspicious_asn" }),
    item({ category: "infrastructure", weight: 20, type: "multiple_anomalous_source_ips" }),
    item({ category: "infrastructure", weight: 15, type: "cloud_vps_indicator" }),
  ];
  const risk = computeRisk("EMAIL-F6", evidence, {
    ...base,
    infrastructureStatus: "AVAILABLE",
  });
  assert.ok((risk.categoryScores?.infrastructure.score ?? 0) <= 100);
  assert.ok((risk.score ?? 0) <= 100);
});
