// INTENTIONALLY INSECURE CODE — for SAST testing only.
const express = require("express");
const ejs = require("ejs");
const { exec } = require("child_process");
const mysql = require("mysql");
const jwt = require("jsonwebtoken");

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // insecure: disable TLS verification

const app = express();
app.set("view engine", "ejs");
app.set("views", __dirname.replace("/src", "/views"));

const JWT_SECRET = "hardcoded-dev-secret"; // insecure hardcoded secret
const DB_PASS = "root"; // insecure hardcoded password

// duplicated function (intentional duplication for Sonar to flag)
function parseUser(qs) {
  const obj = {};
  (qs || "").split("&").forEach(pair => {
    const [k, v] = pair.split("=");
    obj[decodeURIComponent(k || "")] = decodeURIComponent(v || "");
  });
  return obj;
}
function parseUser_dup(qs) { // duplicate of parseUser
  const obj = {};
  (qs || "").split("&").forEach(pair => {
    const [k, v] = pair.split("=");
    obj[decodeURIComponent(k || "")] = decodeURIComponent(v || "");
  });
  return obj;
}

// high cognitive complexity (nested conditionals)
function complex(x) {
  let total = 0;
  for (let i = 0; i < x; i++) {
    if (i % 2 === 0) {
      if (i % 3 === 0) {
        if (i % 5 === 0) {
          for (let j = 0; j < i; j++) {
            if ((i + j) % 7 === 0) {
              total += j;
            } else {
              total -= j % 2 === 0 ? 2 : 3;
            }
          }
        }
      }
    }
  }
  return total;
}

// insecure cookie (missing HttpOnly/Secure flags)
app.get("/login", (req, res) => {
  const token = jwt.sign({ user: "admin" }, JWT_SECRET); // hardcoded claims
  res.setHeader("Set-Cookie", `auth=${token}; Path=/; SameSite=Lax`); // no HttpOnly/Secure
  res.redirect("/");
});

// SQL injection (string concatenation)
app.get("/search", (req, res) => {
  const term = req.query.q || "";
  const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: DB_PASS,
    database: "testdb"
  });
  const sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'"; // vulnerable
  connection.query(sql, (err, rows) => {
    res.render("index", { title: "Search", message: "Results", q: term, rows: rows || [] });
  });
});

// Command injection (user-controlled input to exec)
app.get("/ping", (req, res) => {
  const host = req.query.host || "127.0.0.1";
  exec("ping -c 1 " + host, (err, stdout, stderr) => { // vulnerable
    res.type("text/plain").send(stdout || String(err || stderr));
  });
});

// XSS via unescaped EJS output (use <%- ... %> to not escape)
app.get("/", (req, res) => {
  res.render("index", { title: "Home", message: "Welcome", q: req.query.q || "", rows: [] });
});

// eval on user input (terrible idea)
app.get("/calc", (req, res) => {
  const expr = req.query.expr || "2+2";
  try {
    const out = eval(expr); // vulnerable
    res.send("Result: " + out);
  } catch (e) {
    res.status(400).send("Bad expression");
  }
});

app.listen(3000, () => {
  console.log("Insecure WebApp listening on http://localhost:3000");
});
