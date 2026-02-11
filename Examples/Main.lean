import LeanPQ

open LeanPQ

def main : IO Unit := do
  IO.println "LeanPQ Example -- PostgreSQL Connection Demo"
  IO.println "============================================"

  -- Read connection configuration from environment variables with sensible defaults
  let host ← IO.getEnv "PGHOST" |>.map (·.getD "localhost")
  let portStr ← IO.getEnv "PGPORT" |>.map (·.getD "5432")
  let user ← IO.getEnv "PGUSER" |>.map (·.getD "postgres")
  let database ← IO.getEnv "PGDATABASE" |>.map (·.getD "postgres")
  let password ← IO.getEnv "PGPASSWORD" |>.map (·.getD "")

  IO.println s!"Connecting to PostgreSQL at {host}:{portStr} as {user} to database {database}..."

  let port := portStr.toNat?.getD 5432

  try
    -- Connect to PostgreSQL
    let conn ← Connection.connect {
      host := host
      port := port.toUInt16
      user := user
      database := database
      password := password
    }
    IO.println "Connected successfully!"
    IO.println ""

    -- Run SELECT version() and print the result
    IO.println "Running: SELECT version()"
    IO.println "-------------------------"
    let versionResult ← conn.query "SELECT version()"
    for row in versionResult.rows do
      match row.get? (α := String) 0 with
      | some v => IO.println s!"  {v}"
      | none => IO.println "  (null)"
    IO.println ""

    -- Run a simple query with multiple columns
    IO.println "Running: SELECT 1 AS num, 'hello' AS greeting"
    IO.println "----------------------------------------------"
    let result ← conn.query "SELECT 1 AS num, 'hello' AS greeting"
    for row in result.rows do
      let mut parts : Array String := #[]
      for i in [:result.columns.size] do
        let colName := match result.columns[i]? with
          | some c => c.name
          | none => "?"
        let value := match row.values[i]? with
          | some (some v) => v
          | _ => "(null)"
        parts := parts.push s!"{colName} = {value}"
      IO.println s!"  {String.intercalate ", " parts.toList}"
    IO.println ""

    -- Close the connection
    conn.close
    IO.println "Connection closed. Done!"

  catch e =>
    IO.eprintln s!"Error: {e}"
    IO.Process.exit 1
