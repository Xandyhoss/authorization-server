import {
  pgTable,
  uuid,
  varchar,
  text,
  timestamp,
  jsonb,
} from "drizzle-orm/pg-core";

export const usersTable = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  login: varchar("login", { length: 255 }).notNull().unique(),
  password: varchar("password", { length: 64 }).notNull(),
  user_metadata: jsonb("user_metadata"),
  createdAt: timestamp("created_at").defaultNow(),
});

export const refreshTokensTable = pgTable("refresh_tokens", {
  id: uuid("id").primaryKey().defaultRandom(),
  userId: uuid("user_id").references(() => usersTable.id),
  refreshToken: text("refresh_token").notNull().unique(),
});
