import { z } from "zod";

const unitInterval = z.number().min(0).max(1);

export const llmSemanticSchema = z.object({
  phishingIntent: unitInterval,
  credentialHarvesting: unitInterval,
  financialFraud: unitInterval,
  impersonation: unitInterval,
  socialEngineering: unitInterval,
  attackType: z.string().min(1).max(80),
  summary: z.string().min(1).max(2000),
  recommendedActions: z.array(z.string().max(300)).max(12),
});

export type LlmSemanticOutput = z.infer<typeof llmSemanticSchema>;

export function parseLlmSemanticJson(raw: string): LlmSemanticOutput {
  const trimmed = raw.trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const jsonText = fenced ? fenced[1].trim() : trimmed;
  const parsed: unknown = JSON.parse(jsonText);
  return llmSemanticSchema.parse(parsed);
}

export function aiContentScore(output: LlmSemanticOutput): number {
  return Math.round(
    100 *
      (0.3 * output.phishingIntent +
        0.2 * output.credentialHarvesting +
        0.2 * output.financialFraud +
        0.2 * output.impersonation +
        0.1 * output.socialEngineering)
  );
}
