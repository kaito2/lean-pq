import LeanPQ.ByteUtils
import LeanPQ.Protocol
import LeanPQ.Auth.MD5
import Std.Internal.Async

open LeanPQ.ByteUtils
open LeanPQ.Protocol
open Std.Internal.IO.Async
open Std.Net

namespace LeanPQ

structure ConnConfig where
  host : String := "localhost"
  port : UInt16 := 5432
  user : String := "postgres"
  database : String := ""
  password : String := ""
  deriving Repr

structure Connection where
  socket : TCP.Socket.Client
  config : ConnConfig

namespace Connection

def sendMsg (conn : Connection) (msg : FrontendMsg) : IO Unit := do
  let data := msg.serialize
  (conn.socket.send data).block

def recvExact (conn : Connection) (n : Nat) : IO ByteArray := do
  let mut buf := ByteArray.empty
  let mut remaining := n
  while remaining > 0 do
    match ← (conn.socket.recv? remaining.toUInt64).block with
    | none => throw (.userError "connection closed unexpectedly")
    | some chunk =>
      if chunk.size == 0 then
        throw (.userError "connection closed unexpectedly")
      buf := buf ++ chunk
      remaining := remaining - chunk.size
  return buf

def recvBackendMsg (conn : Connection) : IO BackendMsg := do
  let header ← conn.recvExact 5
  let tag := header.get! 0
  let len := getUInt32BE header 1 |>.1
  let bodyLen := len.toNat - 4
  let body ← if bodyLen > 0 then conn.recvExact bodyLen else pure ByteArray.empty
  return BackendMsg.parse tag body

private def handleAuth (conn : Connection) : IO Unit := do
  for _ in [:100] do
    let msg ← conn.recvBackendMsg
    match msg with
    | .authOk => pure ()
    | .authCleartextPassword =>
      conn.sendMsg (.passwordCleartext conn.config.password)
    | .authMD5Password salt =>
      let hash := Auth.pgMD5Password conn.config.user conn.config.password salt
      conn.sendMsg (.passwordMD5 hash)
    | .readyForQuery _ => return
    | .parameterStatus _ _ => pure ()
    | .backendKeyData _ _ => pure ()
    | .errorResponse fields =>
      let errMsg := fields.filterMap fun (c, s) => if c == 'M' then some s else none
      throw (.userError s!"PostgreSQL error: {errMsg.head?.getD "unknown error"}")
    | .noticeResponse _ => pure ()
    | _ => pure ()
  throw (.userError "authentication: too many messages")

def connect (cfg : ConnConfig) : IO Connection := do
  let db := if cfg.database.isEmpty then cfg.user else cfg.database
  let addrs ← (DNS.getAddrInfo cfg.host (toString cfg.port.toNat) (some .ipv4)).block
  if addrs.isEmpty then
    throw (.userError s!"cannot resolve host: {cfg.host}")
  let ipAddr := addrs[0]!
  let sockAddr : SocketAddress := match ipAddr with
    | .v4 addr => .v4 { addr, port := cfg.port }
    | .v6 addr => .v6 { addr, port := cfg.port }
  let sock ← TCP.Socket.Client.mk
  (sock.connect sockAddr).block
  let conn : Connection := { socket := sock, config := cfg }
  conn.sendMsg (.startup cfg.user db)
  handleAuth conn
  return conn

def close (conn : Connection) : IO Unit := do
  conn.sendMsg .terminate
  (conn.socket.shutdown).block

end Connection
end LeanPQ
