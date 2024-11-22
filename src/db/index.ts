import dotenv from "dotenv";
dotenv.config();

import { drizzle } from "drizzle-orm/node-postgres";
const db = drizzle(process.env.POSTGRES_URL!);

export default db;
