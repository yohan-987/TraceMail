export function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " urltoken ")
    .replace(/[^a-z0-9]+/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 1);
}
