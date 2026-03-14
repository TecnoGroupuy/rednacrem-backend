export const config = {
  awsRegion: process.env.AWS_REGION || process.env.COGNITO_REGION || "us-east-1",
  cognitoUserPoolId: process.env.COGNITO_USER_POOL_ID || "",
  cognitoClientId: process.env.COGNITO_CLIENT_ID || "",
  cognitoDefaultPassword: process.env.COGNITO_TEMP_PASSWORD || "ChangeMe123!",
  cognitoSellerGroup: process.env.COGNITO_SELLER_GROUP || "vendedor",
  db: {
    connectionString: process.env.DATABASE_URL || undefined,
    host: process.env.PGHOST || process.env.DATABASE_HOST,
    port: process.env.PGPORT ? Number(process.env.PGPORT) : process.env.DATABASE_PORT ? Number(process.env.DATABASE_PORT) : 5432,
    user: process.env.PGUSER || process.env.DATABASE_USER,
    password: process.env.PGPASSWORD || process.env.DATABASE_PASSWORD,
    database: process.env.PGDATABASE || process.env.DATABASE_NAME,
    ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : undefined,
  },
};

export function requireEnv(name, value) {
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }

  return value;
}