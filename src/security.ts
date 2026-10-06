export function validDomainPattern(value: string): boolean {
  if (value !== value.toLowerCase() || value.includes("://") || /[/?#:@\\]/.test(value)) return false;
  if (value === "localhost" || value.endsWith(".localhost")) return false;
  if ((value.match(/\*/g) ?? []).length > 1) return false;
  return /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(value);
}

export function hostnameAllowed(hostname: string, patterns: string[]): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return patterns.some((pattern) =>
    pattern.startsWith("*.")
      ? host.endsWith(pattern.slice(1)) && host !== pattern.slice(2)
      : host === pattern
  );
}
