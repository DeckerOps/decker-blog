---
layout: post
title: "Fix It Right: Security Remediation Handbook"
date: 2026-03-15
categories: [remediation]
excerpt: "SQL injection occurs when user-controlled input is concatenated directly into a SQL query. The database interprets the input as SQL syntax rather than data, allowing an attacker to alter query logi..."
slug: fix-it-right-security-remediation-handbook
author: Decker
---

# Fix It Right: Security Remediation Handbook
## Chapter 2: 1. SQL Injection

## 1. SQL Injection

### What it is
SQL injection occurs when user-controlled input is concatenated directly into a SQL query. The database interprets the input as SQL syntax rather than data, allowing an attacker to alter query logic, extract data from any table, bypass authentication, or execute OS-level commands via functions like `xp_cmdshell` (MSSQL) or `INTO OUTFILE` (MySQL).

### Impact
Full database read. Table enumeration. Authentication bypass (` ' OR '1'='1`). Data exfiltration. In misconfigured environments: OS command execution, file read/write, privilege escalation to DBA.

### Detection
```bash
# sqlmap automated scan
sqlmap -u "https://target.com/item?id=1" --batch --level=3 --risk=2

# Manual test — append single quote, observe error
curl "https://target.com/item?id=1'"

# Boolean-based blind test
curl "https://target.com/item?id=1 AND 1=1"   # returns normally
curl "https://target.com/item?id=1 AND 1=2"   # should return different result
```

### Remediation

**Python (psycopg2 / SQLAlchemy)**
```python
# WRONG — never do this
query = f"SELECT * FROM users WHERE username = '{username}'"

# CORRECT — parameterized query (psycopg2)
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))

# CORRECT — SQLAlchemy ORM
user = session.query(User).filter(User.username == username).first()

# CORRECT — SQLAlchemy core with text()
from sqlalchemy import text
result = conn.execute(text("SELECT * FROM users WHERE username = :name"), {"name": username})
```

**Node.js (pg / mysql2)**
```javascript
// WRONG
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)

// CORRECT — pg (PostgreSQL)
const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id])

// CORRECT — mysql2
const [rows] = await conn.execute('SELECT * FROM users WHERE id = ?', [req.params.id])
```

**PHP (PDO)**
```php
// WRONG
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// CORRECT — PDO prepared statement
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');
$stmt->execute([':id' => $_GET['id']]);
$result = $stmt->fetchAll();
```

**Java (JDBC)**
```java
// WRONG
String query = "SELECT * FROM users WHERE name = '" + name + "'";

// CORRECT — PreparedStatement
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
stmt.setString(1, name);
ResultSet rs = stmt.executeQuery();
```

**Additional controls:**
- Use least-privilege DB accounts — the app user should not have DROP, CREATE, or FILE privileges
- Enable WAF rules for SQLi patterns (ModSecurity CRS ruleset)
- For MSSQL: disable `xp_cmdshell` — `EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;`

### Verification
```bash
# sqlmap should return "all tested parameters do not appear to be injectable"
sqlmap -u "https://target.com/item?id=1" --batch

# Manual: single quote in all parameters should return generic error, not SQL error
curl "https://target.com/item?id=1'"
# Expected: generic 400/500, no SQL syntax in response body
```

### Tools
sqlmap, Burp Suite Scanner, OWASP ZAP, manual testing

---
