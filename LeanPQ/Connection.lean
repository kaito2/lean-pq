import LeanPQ.ByteUtils
import LeanPQ.Protocol
import LeanPQ.Auth.MD5
import LeanPQ.Auth.SCRAM
import LeanPQ.Error
import LeanPQ.SSL
import Std.Internal.Async

open LeanPQ.ByteUtils
open LeanPQ.Protocol
open Std.Internal.IO.Async
open Std.Net

namespace LeanPQ

-- ============================================================
-- Transport abstraction (plain TCP or SSL)
-- ============================================================

inductive Transport where
  | plain (sock : TCP.Socket.Client)
  | ssl (sock : TCP.Socket.Client) (sslConn : SSL.SSLConnection)

structure ConnConfig where
  host : String := "localhost"
  port : UInt16 := 5432
  user : String := "postgres"
  database : String := ""
  password : String := ""
  sslMode : SSL.SSLMode := .disable
  deriving Repr

structure Connection where
  transport : Transport
  config : ConnConfig

namespace Connection

-- ============================================================
-- Low-level send/recv over Transport
-- ============================================================

private def sendBytes (conn : Connection) (data : ByteArray) : IO Unit :=
  match conn.transport with
  | .plain sock => (sock.send data).block
  | .ssl _ sslConn => sslConn.send data

def sendMsg (conn : Connection) (msg : FrontendMsg) : IO Unit :=
  conn.sendBytes msg.serialize

def recvExact (conn : Connection) (n : Nat) : IO ByteArray := do
  let mut buf := ByteArray.empty
  let mut remaining := n
  while remaining > 0 do
    let chunk ← match conn.transport with
      | .plain sock =>
        match ← (sock.recv? remaining.toUInt64).block with
        | none => PgError.toIO .connectionClosed
        | some chunk =>
          if chunk.size == 0 then PgError.toIO .connectionClosed
          pure chunk
      | .ssl _ sslConn =>
        match ← sslConn.recv remaining.toUInt64 with
        | none => PgError.toIO .connectionClosed
        | some chunk =>
          if chunk.size == 0 then PgError.toIO .connectionClosed
          pure chunk
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

-- ============================================================
-- Nonce generation for SCRAM
-- ============================================================

private def generateNonce : IO String := do
  let chars := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toList.toArray
  let mut s := ""
  for _ in [:32] do
    let n ← IO.rand 0 (chars.size - 1)
    s := s.push chars[n]!
  return s

-- ============================================================
-- Authentication
-- ============================================================

private def handleAuth (conn : Connection) : IO Unit := do
  let scramRef ← IO.mkRef (none : Option Auth.ScramState)
  let sigRef ← IO.mkRef (none : Option ByteArray)
  for _ in [:100] do
    let msg ← conn.recvBackendMsg
    match msg with
    | .authOk => pure ()
    | .authCleartextPassword =>
      conn.sendMsg (.passwordCleartext conn.config.password)
    | .authMD5Password salt =>
      let hash := Auth.pgMD5Password conn.config.user conn.config.password salt
      conn.sendMsg (.passwordMD5 hash)
    | .authSASL mechanisms =>
      if !mechanisms.contains "SCRAM-SHA-256" then
        PgError.toIO (.authFailed "server does not support SCRAM-SHA-256")
      let nonce ← generateNonce
      let (clientFirstMsg, scramState) := Auth.scramClientFirstMessage conn.config.user nonce
      conn.sendMsg (.saslInitialResponse "SCRAM-SHA-256" clientFirstMsg.toUTF8)
      scramRef.set (some scramState)
    | .authSASLContinue data =>
      match ← scramRef.get with
      | none => PgError.toIO (.protocolError "unexpected AuthSASLContinue")
      | some scramState =>
        let serverFirstMsg := String.fromUTF8! data
        match Auth.scramClientFinalMessage scramState conn.config.password serverFirstMsg with
        | none => PgError.toIO (.authFailed "failed to process SCRAM server challenge")
        | some (clientFinalMsg, expectedServerSig) =>
          conn.sendMsg (.saslResponse clientFinalMsg.toUTF8)
          sigRef.set (some expectedServerSig)
    | .authSASLFinal data =>
      match ← sigRef.get with
      | none => PgError.toIO (.protocolError "unexpected AuthSASLFinal")
      | some expectedServerSig =>
        let serverFinalMsg := String.fromUTF8! data
        if !Auth.scramVerifyServerFinal serverFinalMsg expectedServerSig then
          PgError.toIO (.authFailed "SCRAM server signature verification failed")
    | .readyForQuery _ => return
    | .parameterStatus _ _ => pure ()
    | .backendKeyData _ _ => pure ()
    | .errorResponse fields => (PgError.fromFields fields).toIO
    | .noticeResponse _ => pure ()
    | _ => pure ()
  PgError.toIO (.protocolError "authentication: too many messages")

-- ============================================================
-- SSL negotiation
-- ============================================================

@[extern "lean_pq_socket_fd"]
private opaque socketFd : @& TCP.Socket.Client → IO UInt32

private def negotiateSSL (sock : TCP.Socket.Client) (mode : SSL.SSLMode) : IO Transport := do
  match mode with
  | .disable => return .plain sock
  | _ =>
    -- Send SSLRequest
    (sock.send SSL.sslRequestMessage).block
    -- Read 1-byte response
    let resp ← match ← (sock.recv? 1).block with
      | none => PgError.toIO (.sslError "connection closed during SSL negotiation")
      | some buf =>
        if buf.size == 0 then PgError.toIO (.sslError "empty response to SSLRequest")
        pure (buf.get! 0)
    if SSL.isSSLAccepted resp then
      -- Server accepted SSL, perform TLS handshake
      let ctx ← SSL.SSLContext.mk
      let fd ← socketFd sock
      let sslConn ← ctx.connect fd
      return .ssl sock sslConn
    else
      -- Server declined SSL
      match mode with
      | .require => PgError.toIO (.sslError "server does not support SSL")
      | _ => return .plain sock

-- ============================================================
-- Connect / Close
-- ============================================================

def connect (cfg : ConnConfig) : IO Connection := do
  let db := if cfg.database.isEmpty then cfg.user else cfg.database
  let addrs ← (DNS.getAddrInfo cfg.host (toString cfg.port.toNat) (some .ipv4)).block
  if addrs.isEmpty then
    PgError.toIO (.connectionFailed s!"cannot resolve host: {cfg.host}")
  let ipAddr := addrs[0]!
  let sockAddr : SocketAddress := match ipAddr with
    | .v4 addr => .v4 { addr, port := cfg.port }
    | .v6 addr => .v6 { addr, port := cfg.port }
  let sock ← TCP.Socket.Client.mk
  (sock.connect sockAddr).block
  let transport ← negotiateSSL sock cfg.sslMode
  let conn : Connection := { transport, config := cfg }
  conn.sendMsg (.startup cfg.user db)
  handleAuth conn
  return conn

def close (conn : Connection) : IO Unit := do
  conn.sendMsg .terminate
  match conn.transport with
  | .plain sock => (sock.shutdown).block
  | .ssl sock sslConn =>
    sslConn.shutdown
    (sock.shutdown).block

end Connection
end LeanPQ
