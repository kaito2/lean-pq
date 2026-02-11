import LeanPQ.Types

namespace LeanPQ

/-- Metadata for a single column in a query result. -/
structure Column where
  name : String
  tableOid : UInt32 := 0
  columnNumber : UInt16 := 0
  typeOid : UInt32 := 0
  formatCode : UInt16 := 0
  deriving Repr, BEq

/-- A single row of query results. Values are Option String (None = SQL NULL). -/
structure Row where
  columns : Array Column
  values : Array (Option String)
  deriving Repr

namespace Row

/-- Get a column value by index as raw Option String. -/
def getOpt (row : Row) (col : Nat) : Option (Option String) :=
  row.values[col]?

/-- Get a column value by index, converting with FromPg. Returns none if index out of range or NULL. -/
def get? (row : Row) (col : Nat) [FromPg α] : Option α := do
  let val ← row.values[col]?
  let str ← val
  FromPg.fromPg str

/-- Get a column value by name. -/
def getByName? (row : Row) (name : String) [FromPg α] : Option α := do
  let idx ← row.columns.findIdx? (·.name == name)
  row.get? idx

/-- Check if a column is NULL. -/
def isNull (row : Row) (col : Nat) : Bool :=
  match row.values[col]? with
  | some none => true
  | _ => false

end Row

/-- Result of a SELECT query. -/
structure QueryResult where
  columns : Array Column
  rows : Array Row
  deriving Repr

namespace QueryResult

/-- Number of rows. -/
def rowCount (r : QueryResult) : Nat := r.rows.size

/-- Number of columns. -/
def columnCount (r : QueryResult) : Nat := r.columns.size

/-- Get a specific row. -/
def getRow (r : QueryResult) (idx : Nat) : Option Row := r.rows[idx]?

/-- Map a function over all rows to extract typed values. -/
def map (r : QueryResult) (f : Row → Option α) : Array α :=
  r.rows.filterMap f

/-- Get all values from a single column as typed array. -/
def getColumn (r : QueryResult) (col : Nat) [FromPg α] : Array α :=
  r.rows.filterMap (·.get? col)

end QueryResult

/-- Result of a non-SELECT query (INSERT, UPDATE, DELETE, etc.). -/
structure ExecResult where
  tag : String
  affectedRows : Nat
  deriving Repr

namespace ExecResult

/-- Parse the affected rows count from a command tag. -/
def fromTag (tag : String) : ExecResult :=
  let parts := tag.splitOn " "
  let n := match parts.getLast? with
    | some s => s.toNat?.getD 0
    | none => 0
  { tag, affectedRows := n }

end ExecResult

end LeanPQ
