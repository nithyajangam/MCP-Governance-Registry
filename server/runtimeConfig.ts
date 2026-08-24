const REQUIRED_RENDER_VARIABLES = ["DATABASE_URL", "JWT_SECRET", "DASHBOARD_ACCESS_KEY"] as const;

export function validateRuntimeEnvironment(environment: NodeJS.ProcessEnv = process.env) {
  if (environment.VITE_PORTABLE_AUTH !== "true") return { portable: false, missing: [] as string[] };
  const missing: string[] = REQUIRED_RENDER_VARIABLES.filter(key => !environment[key]?.trim());
  if (environment.TIDB_ENABLE_SSL !== "true") missing.push("TIDB_ENABLE_SSL=true");
  return { portable: true, missing };
}

export function assertRuntimeEnvironment() {
  const result = validateRuntimeEnvironment();
  if (result.missing.length) {
    throw new Error(`Render deployment is missing required environment variables: ${result.missing.join(", ")}`);
  }
}
