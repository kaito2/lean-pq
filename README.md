# LeanPQ

A pure Lean 4 PostgreSQL client library implementing the PostgreSQL wire protocol v3.

## Features

- Pure Lean 4 implementation (no C/FFI dependencies)
- PostgreSQL wire protocol v3
- MD5 and cleartext password authentication
- Simple query protocol
- Extended query protocol with parameterized queries
- Type-safe result handling with `FromPg`/`ToPg` type classes

## Requirements

- Lean 4 v4.27.0 or later
- Lake build system

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

## API Overview

| Module | Description |
|---|---|
| `ByteUtils` | Low-level byte encoding and decoding utilities |
| `Protocol` | PostgreSQL wire protocol message types and serialization |
| `Auth.MD5` | MD5 password authentication |
| `Types` | PostgreSQL type OIDs and the `FromPg`/`ToPg` type classes |
| `Connection` | Connection management and configuration |
| `Query` | Simple and extended query execution |
| `Result` | Query result representation and row access |

## License

MIT
