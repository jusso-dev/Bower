export function formatDate(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(new Date(value));
}

/** First eight hex characters of a sha256 hash; "default" and missing values stay readable. */
export function shortHash(value: string | null | undefined): string {
  if (!value) {
    return "not reported";
  }
  return value === "default" ? "default" : value.replace("sha256:", "").slice(0, 8);
}
