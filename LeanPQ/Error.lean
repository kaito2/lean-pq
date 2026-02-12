namespace LeanPQ

/-- Structured representation of an error reported by PostgreSQL. -/
structure ServerError where
  severity : String          -- e.g., "ERROR", "FATAL"
  code : String              -- SQLSTATE code, e.g., "42P01"
  message : String           -- Primary error message
  detail : Option String := none
  hint : Option String := none
  deriving Repr

/-- Parse a PostgreSQL error/notice field list into a `ServerError`.

Field codes:
- 'S' = severity
- 'C' = code
- 'M' = message
- 'D' = detail
- 'H' = hint
-/
def ServerError.fromFields (fields : List (Char × String)) : ServerError :=
  let lookup (c : Char) : Option String :=
    fields.find? (fun p => p.1 == c) |>.map Prod.snd
  { severity := lookup 'S' |>.getD "ERROR"
    code     := lookup 'C' |>.getD "00000"
    message  := lookup 'M' |>.getD "unknown error"
    detail   := lookup 'D'
    hint     := lookup 'H' }

instance : ToString ServerError where
  toString e :=
    let base := s!"{e.severity} ({e.code}): {e.message}"
    let base := match e.detail with
      | some d => base ++ s!"\nDETAIL: {d}"
      | none   => base
    match e.hint with
      | some h => base ++ s!"\nHINT: {h}"
      | none   => base

/-- Structured error type for the LeanPQ PostgreSQL client library,
replacing ad-hoc `IO.userError` string errors. -/
inductive PgError where
  | connectionFailed (reason : String)
  | authFailed (reason : String)
  | serverError (err : ServerError)
  | protocolError (msg : String)
  | sslError (msg : String)
  | connectionClosed
  deriving Repr

instance : ToString PgError where
  toString
    | .connectionFailed reason => s!"Connection failed: {reason}"
    | .authFailed reason       => s!"Authentication failed: {reason}"
    | .serverError err         => toString err
    | .protocolError msg       => s!"Protocol error: {msg}"
    | .sslError msg            => s!"SSL error: {msg}"
    | .connectionClosed        => "Connection closed"

/-- Throw a `PgError` as an `IO.Error`. -/
def PgError.toIO : PgError → IO α :=
  fun e => throw (.userError (toString e))

/-- Create a `PgError.serverError` from a PostgreSQL error/notice field list. -/
def PgError.fromFields (fields : List (Char × String)) : PgError :=
  .serverError (ServerError.fromFields fields)

end LeanPQ
