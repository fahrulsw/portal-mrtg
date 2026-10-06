const Database = require("better-sqlite3");
const db = new Database("portal.db");
db.pragma("journal_mode = WAL");

const cols = db.prepare("PRAGMA table_info(customers)").all().map((c) => c.name);

const CUSTOMERS_DDL = (name) => `
CREATE TABLE ${name} (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1
)`;

if (cols.length === 0) {
  db.exec(CUSTOMERS_DDL("customers"));
} else if (!cols.includes("username")) {
  // Migrasi dari versi lama (login pakai email): email lama menjadi username.
  db.pragma("foreign_keys = OFF");
  db.transaction(() => {
    db.exec(CUSTOMERS_DDL("customers_new"));
    db.exec(`INSERT INTO customers_new (id, name, username, password_hash)
             SELECT id, name, lower(email), password_hash FROM customers`);
    db.exec("DROP TABLE customers");
    db.exec("ALTER TABLE customers_new RENAME TO customers");
  })();
}
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY,
  customer_id INTEGER NOT NULL REFERENCES customers(id),
  label TEXT NOT NULL,           -- contoh: "Dedicated 50 Mbps - Purwodadi"
  lnms_port_id INTEGER NOT NULL  -- port_id di LibreNMS
);
CREATE INDEX IF NOT EXISTS idx_services_customer ON services(customer_id);
`);

module.exports = db;
