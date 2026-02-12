/-
  LeanPQ.Protocol — PostgreSQL wire protocol v3 message types and serialization.
-/
import LeanPQ.ByteUtils

open LeanPQ.ByteUtils

namespace LeanPQ.Protocol

-- ============================================================
-- Frontend messages (client → server)
-- ============================================================

inductive FrontendMsg where
  | startup (user : String) (database : String)
  | passwordCleartext (password : String)
  | passwordMD5 (hash : String)
  | query (sql : String)
  | parse (name : String) (sql : String) (paramTypes : Array UInt32)
  | bind (portal : String) (stmt : String) (params : Array (Option String))
  | describe (type : Char) (name : String)
  | execute (portal : String) (maxRows : UInt32)
  | sync
  | terminate
  | saslInitialResponse (mechanism : String) (data : ByteArray)
  | saslResponse (data : ByteArray)

-- ============================================================
-- Backend messages (server → client)
-- ============================================================

structure ColumnDesc where
  name : String
  tableOid : UInt32
  columnNumber : UInt16
  typeOid : UInt32
  typeSize : Int16
  typeMod : Int32
  formatCode : UInt16

inductive BackendMsg where
  | authOk
  | authCleartextPassword
  | authMD5Password (salt : ByteArray)
  | parameterStatus (name : String) (value : String)
  | backendKeyData (pid : UInt32) (secretKey : UInt32)
  | readyForQuery (txStatus : Char)
  | rowDescription (columns : Array ColumnDesc)
  | dataRow (values : Array (Option String))
  | commandComplete (tag : String)
  | errorResponse (fields : List (Char × String))
  | noticeResponse (fields : List (Char × String))
  | authSASL (mechanisms : Array String)
  | authSASLContinue (data : ByteArray)
  | authSASLFinal (data : ByteArray)
  | emptyQueryResponse
  | parseComplete
  | bindComplete
  | noData
  | unknown (tag : UInt8) (payload : ByteArray)

-- ============================================================
-- Serialization helpers
-- ============================================================

/-- Build a message with tag byte and length prefix.
    The callback writes the body; we prepend tag + length (including the 4 length bytes). -/
private def buildTaggedMsg (tag : UInt8) (body : ByteArray) : ByteArray :=
  let len := (body.size + 4).toUInt32
  let buf := ByteArray.empty |>.push tag
  let buf := putUInt32BE buf len
  buf.append body

-- ============================================================
-- FrontendMsg.serialize
-- ============================================================

def FrontendMsg.serialize : FrontendMsg → ByteArray
  | .startup user database =>
    -- StartupMessage has no tag byte: Int32 length, Int32 protocol, then params
    let body := ByteArray.empty
    let body := putCString body "user"
    let body := putCString body user
    let body := putCString body "database"
    let body := putCString body database
    let body := body.push 0  -- terminator
    let len := (body.size + 8).toUInt32  -- +4 for length field, +4 for protocol version
    let buf := ByteArray.empty
    let buf := putUInt32BE buf len
    let buf := putUInt32BE buf 196608  -- protocol version 3.0
    buf.append body
  | .passwordCleartext password =>
    let body := putCString ByteArray.empty password
    buildTaggedMsg 'p'.val.toUInt8 body
  | .passwordMD5 hash =>
    let body := putCString ByteArray.empty hash
    buildTaggedMsg 'p'.val.toUInt8 body
  | .query sql =>
    let body := putCString ByteArray.empty sql
    buildTaggedMsg 'Q'.val.toUInt8 body
  | .parse name sql paramTypes =>
    let body := ByteArray.empty
    let body := putCString body name
    let body := putCString body sql
    let body := putUInt16BE body paramTypes.size.toUInt16
    let body := Id.run do
      let mut b := body
      for oid in paramTypes do
        b := putUInt32BE b oid
      return b
    buildTaggedMsg 'P'.val.toUInt8 body
  | .bind portal stmt params =>
    let body := ByteArray.empty
    let body := putCString body portal
    let body := putCString body stmt
    let body := putUInt16BE body 0  -- 0 param format codes (all text)
    let body := putUInt16BE body params.size.toUInt16
    let body := Id.run do
      let mut b := body
      for p in params do
        match p with
        | none =>
          b := putInt32BE b (-1 : Int32)  -- NULL
        | some s =>
          let bytes := s.toUTF8
          b := putUInt32BE b bytes.size.toUInt32
          b := b.append bytes
      return b
    let body := putUInt16BE body 0  -- 0 result format codes (all text)
    buildTaggedMsg 'B'.val.toUInt8 body
  | .describe type name =>
    let body := ByteArray.empty |>.push type.val.toUInt8
    let body := putCString body name
    buildTaggedMsg 'D'.val.toUInt8 body
  | .execute portal maxRows =>
    let body := ByteArray.empty
    let body := putCString body portal
    let body := putUInt32BE body maxRows
    buildTaggedMsg 'E'.val.toUInt8 body
  | .sync =>
    buildTaggedMsg 'S'.val.toUInt8 ByteArray.empty
  | .terminate =>
    buildTaggedMsg 'X'.val.toUInt8 ByteArray.empty
  | .saslInitialResponse mechanism data =>
    let body := ByteArray.empty
    let body := putCString body mechanism
    let body := putInt32BE body data.size.toInt32
    let body := body.append data
    buildTaggedMsg 'p'.val.toUInt8 body
  | .saslResponse data =>
    buildTaggedMsg 'p'.val.toUInt8 data

-- ============================================================
-- BackendMsg.parse
-- ============================================================

private def parseErrorFields (payload : ByteArray) (offset : Nat) : List (Char × String) :=
  let rec loop (off : Nat) (acc : List (Char × String)) (fuel : Nat) : List (Char × String) :=
    match fuel with
    | 0 => acc.reverse
    | fuel + 1 =>
      if off >= payload.size then acc.reverse
      else
        let (b, off) := getByte payload off
        if b == 0 then acc.reverse
        else
          let (s, off) := getCString payload off
          let ch := Char.ofNat b.toNat
          loop off ((ch, s) :: acc) fuel
  loop offset [] (payload.size + 1)

private def parseRowDescription (payload : ByteArray) (offset : Nat) : Array ColumnDesc :=
  let (numCols, off) := getUInt16BE payload offset
  let n := numCols.toNat
  Id.run do
    let mut cols : Array ColumnDesc := #[]
    let mut o := off
    for _ in [:n] do
      let (name, o') := getCString payload o
      let (tableOid, o') := getUInt32BE payload o'
      let (colNum, o') := getUInt16BE payload o'
      let (typeOid, o') := getUInt32BE payload o'
      let (typeSize, o') := getInt16BE payload o'
      let (typeMod, o') := getInt32BE payload o'
      let (fmtCode, o') := getUInt16BE payload o'
      cols := cols.push {
        name := name
        tableOid := tableOid
        columnNumber := colNum
        typeOid := typeOid
        typeSize := typeSize
        typeMod := typeMod
        formatCode := fmtCode
      }
      o := o'
    return cols

private def parseDataRow (payload : ByteArray) (offset : Nat) : Array (Option String) :=
  let (numCols, off) := getUInt16BE payload offset
  let n := numCols.toNat
  Id.run do
    let mut vals : Array (Option String) := #[]
    let mut o := off
    for _ in [:n] do
      let (lenI32, o') := getInt32BE payload o
      if lenI32.toInt == -1 then
        vals := vals.push none
        o := o'
      else
        let len := lenI32.toUInt32.toNat
        let (bytes, o') := getBytes payload o' len
        vals := vals.push (some (String.fromUTF8! bytes))
        o := o'
    return vals

def BackendMsg.parse (tag : UInt8) (payload : ByteArray) : BackendMsg :=
  match tag with
  | 82 => -- 'R' Authentication
    let (authType, _off) := getUInt32BE payload 0
    if authType == 0 then .authOk
    else if authType == 3 then .authCleartextPassword
    else if authType == 5 then
      let (salt, _) := getBytes payload 4 4
      .authMD5Password salt
    else if authType == 10 then
      -- AuthenticationSASL: list of mechanism names (null-terminated, empty string terminates)
      let mechanisms := Id.run do
        let mut mechs : Array String := #[]
        let mut off := 4
        for _ in [:20] do
          if off >= payload.size then return mechs
          let (s, newOff) := getCString payload off
          if s.isEmpty then return mechs
          mechs := mechs.push s
          off := newOff
        return mechs
      .authSASL mechanisms
    else if authType == 11 then
      .authSASLContinue (payload.extract 4 payload.size)
    else if authType == 12 then
      .authSASLFinal (payload.extract 4 payload.size)
    else .unknown tag payload
  | 83 => -- 'S' ParameterStatus
    let (name, off) := getCString payload 0
    let (value, _) := getCString payload off
    .parameterStatus name value
  | 75 => -- 'K' BackendKeyData
    let (pid, off) := getUInt32BE payload 0
    let (key, _) := getUInt32BE payload off
    .backendKeyData pid key
  | 90 => -- 'Z' ReadyForQuery
    let (b, _) := getByte payload 0
    .readyForQuery (Char.ofNat b.toNat)
  | 84 => -- 'T' RowDescription
    .rowDescription (parseRowDescription payload 0)
  | 68 => -- 'D' DataRow
    .dataRow (parseDataRow payload 0)
  | 67 => -- 'C' CommandComplete
    let (s, _) := getCString payload 0
    .commandComplete s
  | 69 => -- 'E' ErrorResponse
    .errorResponse (parseErrorFields payload 0)
  | 78 => -- 'N' NoticeResponse
    .noticeResponse (parseErrorFields payload 0)
  | 73 => -- 'I' EmptyQueryResponse
    .emptyQueryResponse
  | 49 => -- '1' ParseComplete
    .parseComplete
  | 50 => -- '2' BindComplete
    .bindComplete
  | 110 => -- 'n' NoData
    .noData
  | _ => .unknown tag payload

end LeanPQ.Protocol
