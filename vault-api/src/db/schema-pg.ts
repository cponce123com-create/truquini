import { pgTable, uuid, text, integer, timestamp, uniqueIndex } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: uuid("id").defaultRandom().primaryKey(),
  username: text("username").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const vaultBlobs = pgTable(
  "vault_blobs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    salt: text("salt").notNull(),
    iv: text("iv").notNull(),
    data: text("data").notNull(),
    version: integer("version").default(1).notNull(),
    updatedAt: timestamp("updated_at").defaultNow().notNull(),
  },
  (table) => ({
    userUnique: uniqueIndex("vault_blobs_user_id_unique").on(table.userId),
  })
);
