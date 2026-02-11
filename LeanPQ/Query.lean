import LeanPQ.Connection
import LeanPQ.Result
import LeanPQ.Protocol

open LeanPQ.Protocol

namespace LeanPQ

namespace Connection

private def collectRows (conn : Connection) : IO (Array ColumnDesc × Array (Array (Option String)) × String) := do
  let columnsRef ← IO.mkRef (α := Array ColumnDesc) #[]
  let rowsRef ← IO.mkRef (α := Array (Array (Option String))) #[]
  let tagRef ← IO.mkRef ""
  for _ in [:10000] do
    let msg ← conn.recvBackendMsg
    match msg with
    | .rowDescription cols =>
      columnsRef.set cols
    | .dataRow vals =>
      rowsRef.modify (·.push vals)
    | .commandComplete t =>
      tagRef.set t
    | .readyForQuery _ =>
      let columns ← columnsRef.get
      let rows ← rowsRef.get
      let tag ← tagRef.get
      return (columns, rows, tag)
    | .emptyQueryResponse => pure ()
    | .errorResponse fields =>
      let errMsg := fields.filterMap fun (c, s) => if c == 'M' then some s else none
      throw (.userError s!"PostgreSQL error: {errMsg.head?.getD "unknown error"}")
    | .noticeResponse _ => pure ()
    | .parseComplete => pure ()
    | .bindComplete => pure ()
    | .noData => pure ()
    | _ => pure ()
  throw (.userError "query: too many messages")

private def toQueryResult (cols : Array ColumnDesc) (rows : Array (Array (Option String))) : QueryResult :=
  let columns := cols.map fun c => {
    name := c.name
    tableOid := c.tableOid
    columnNumber := c.columnNumber
    typeOid := c.typeOid
    formatCode := c.formatCode : Column
  }
  let resultRows := rows.map fun vals => { columns, values := vals : Row }
  { columns, rows := resultRows }

def query (conn : Connection) (sql : String) : IO QueryResult := do
  conn.sendMsg (.query sql)
  let (cols, rows, _) ← collectRows conn
  return toQueryResult cols rows

def exec (conn : Connection) (sql : String) : IO ExecResult := do
  conn.sendMsg (.query sql)
  let (_, _, tag) ← collectRows conn
  return ExecResult.fromTag tag

def queryParams (conn : Connection) (sql : String) (params : Array String) : IO QueryResult := do
  let paramOpts := params.map (some ·)
  conn.sendMsg (.parse "" sql #[])
  conn.sendMsg (.bind "" "" paramOpts)
  conn.sendMsg (.describe 'P' "")
  conn.sendMsg (.execute "" 0)
  conn.sendMsg .sync
  let (cols, rows, _) ← collectRows conn
  return toQueryResult cols rows

def execParams (conn : Connection) (sql : String) (params : Array String) : IO ExecResult := do
  let paramOpts := params.map (some ·)
  conn.sendMsg (.parse "" sql #[])
  conn.sendMsg (.bind "" "" paramOpts)
  conn.sendMsg (.execute "" 0)
  conn.sendMsg .sync
  let (_, _, tag) ← collectRows conn
  return ExecResult.fromTag tag

end Connection
end LeanPQ
