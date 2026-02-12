# LeanPQ

A pure Lean 4 PostgreSQL client library implementing the PostgreSQL wire protocol v3.

## Features

- PostgreSQL wire protocol v3
- MD5 and cleartext password authentication
- SCRAM-SHA-256 authentication (PostgreSQL 10+ default)
- SSL/TLS encryption via OpenSSL FFI
- Simple query protocol
- Extended query protocol with parameterized queries
- Type-safe result handling with `FromPg`/`ToPg` type classes
- Structured error types (PgError) for better error handling

## Requirements

- Lean 4 v4.27.0 or later
- Lake build system
- OpenSSL (`libssl-dev` on Ubuntu, `brew install openssl` on macOS) for SSL/TLS support

## Installation

Add LeanPQ as a dependency in your `lakefile.lean`:

```lean
require «lean-pq» from git
  "https://github.com/YOUR_USERNAME/lean-pq" @ "main"
```

Then run:

```sh
lake update
lake build
```

## Usage

```lean
import LeanPQ

open LeanPQ

def main : IO Unit := do
  let conn ← Connection.connect {
    host := "localhost"
    port := 5432
    user := "postgres"
    database := "mydb"
    password := "secret"
    sslMode := .prefer  -- .disable, .prefer, or .require
  }

  -- Simple query
  let result ← conn.query "SELECT id, name FROM users"
  for row in result.rows do
    let id := row.get? (α := Nat) 0
    let name := row.get? (α := String) 1
    IO.println s!"id={id}, name={name}"

  -- Parameterized query
  let result ← conn.queryParams "SELECT * FROM users WHERE id = $1" #["42"]
  IO.println s!"rows: {result.rowCount}"

  -- Execute (INSERT/UPDATE/DELETE)
  let execResult ← conn.exec "DELETE FROM old_data"
  IO.println s!"affected: {execResult.affectedRows}"

  conn.close
```

## Error Handling

```lean
-- Errors are thrown as IO.Error with structured PgError information
-- PgError variants: connectionFailed, authFailed, serverError, protocolError, sslError, connectionClosed
```

## API Overview

| Module | Description |
|---|---|
| `ByteUtils` | Low-level byte encoding and decoding utilities |
| `Protocol` | PostgreSQL wire protocol message types and serialization |
| `Error` | Structured error types (PgError, ServerError) |
| `Auth.MD5` | MD5 password authentication |
| `Auth.SHA256` | SHA-256 hash implementation |
| `Auth.HMAC` | HMAC-SHA-256 |
| `Auth.Base64` | Base64 encode/decode |
| `Auth.SCRAM` | SCRAM-SHA-256 client authentication |
| `SSL` | SSL/TLS support via OpenSSL FFI |
| `Types` | PostgreSQL type OIDs and the `FromPg`/`ToPg` type classes |
| `Connection` | Connection management and configuration |
| `Query` | Simple and extended query execution |
| `Result` | Query result representation and row access |

## License

MIT
