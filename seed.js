// Membuat (atau mereset) akun ADMIN. Pelanggan dikelola lewat halaman admin setelah login.
//
// Pemakaian:
//   node seed.js admin <username> <password> "<Nama>"
// Contoh:
//   node seed.js admin admin 'PasswordKuat123' "Administrator"
const bcrypt = require("bcrypt");
const db = require("./db");

const [cmd, usernameRaw, password, name] = process.argv.slice(2);
if (cmd !== "admin" || !usernameRaw || !password || !name) {
  console.error('Pemakaian: node seed.js admin <username> <password> "<Nama>"');
  process.exit(1);
}
if (password.length < 8) { console.error("Password minimal 8 karakter."); process.exit(1); }

const username = usernameRaw.trim().toLowerCase();
const hash = bcrypt.hashSync(password, 12);
const ex = db.prepare("SELECT id FROM customers WHERE username = ?").get(username);
if (ex) {
  db.prepare("UPDATE customers SET name = ?, password_hash = ?, is_admin = 1, active = 1 WHERE id = ?")
    .run(name, hash, ex.id);
  console.log(`Akun "${username}" dijadikan admin dan password direset.`);
} else {
  db.prepare("INSERT INTO customers (name, username, password_hash, is_admin) VALUES (?, ?, ?, 1)")
    .run(name, username, hash);
  console.log(`Admin dibuat: ${username}`);
}