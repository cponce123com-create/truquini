import { sqliteTable, text, integer, uniqueIndex } from "drizzle-orm/sqlite-core";
import crypto from "node:crypto";

export const users = sqliteTable("users", {
  id: text("id")
    .primaryKey()
    .$defaultFn(() => crypto.randomUUID()),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  createdAt: text("created_at")
    .notNull()
    .$defaultFn(() => new Date().toISOString()),
});

export const vaultBlobs = sqliteTable(
  "vault_blobs",
  {
    id: text("id")
      .primaryKey()
      .$defaultFn(() => crypto.randomUUID()),
    userId: text("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    salt: text("salt").notNull(),
    iv: text("iv").notNull(),
    data: text("data").notNull(),
    version: integer("version").default(1).notNull(),
    updatedAt: text("updated_at")
      .notNull()
      .$defaultFn(() => new Date().toISOString()),
  },
  (table) => ({
    userUnique: uniqueIndex("vault_blobs_user_id_unique").on(table.userId),
  })
);
