/-
  LeanPQ.SSL — SSL/TLS support for PostgreSQL connections via OpenSSL FFI.

  This module provides:
  - Opaque types for SSL context and connection handles
  - FFI bindings to OpenSSL (create context, handshake, send, recv, shutdown)
  - SSLMode enumeration for connection configuration
  - The SSLRequest wire protocol message for PostgreSQL SSL negotiation
-/
import LeanPQ.ByteUtils

namespace LeanPQ.SSL

-- ============================================================
-- Opaque types for SSL handles
-- ============================================================

/-- An SSL context (wraps OpenSSL SSL_CTX*).
    Created once and reused for multiple connections. -/
opaque SSLContext.nonemptyType : NonemptyType
def SSLContext : Type := SSLContext.nonemptyType.type
instance : Nonempty SSLContext := SSLContext.nonemptyType.property

/-- An SSL connection (wraps OpenSSL SSL*).
    Represents an active TLS session over a file descriptor. -/
opaque SSLConnection.nonemptyType : NonemptyType
def SSLConnection : Type := SSLConnection.nonemptyType.type
instance : Nonempty SSLConnection := SSLConnection.nonemptyType.property

-- ============================================================
-- FFI declarations
-- ============================================================

/-- Initialize OpenSSL and create a new TLS client context.
    The context is configured with TLS 1.2+ and default CA paths. -/
@[extern "lean_pq_ssl_ctx_new"]
opaque SSLContext.mk : IO SSLContext

/-- Perform a TLS handshake on an existing file descriptor.
    The fd should already be connected to a PostgreSQL server that
    has accepted the SSLRequest. -/
@[extern "lean_pq_ssl_connect"]
opaque SSLContext.connect (ctx : @& SSLContext) (fd : UInt32) : IO SSLConnection

/-- Send data over an SSL connection. Blocks until all bytes are written. -/
@[extern "lean_pq_ssl_send"]
opaque SSLConnection.send (conn : @& SSLConnection) (data : @& ByteArray) : IO Unit

/-- Receive up to maxBytes from an SSL connection.
    Returns `none` if the connection has been closed. -/
@[extern "lean_pq_ssl_recv"]
opaque SSLConnection.recv (conn : @& SSLConnection) (maxBytes : UInt64) : IO (Option ByteArray)

/-- Perform a bidirectional SSL shutdown (sends close_notify). -/
@[extern "lean_pq_ssl_shutdown"]
opaque SSLConnection.shutdown (conn : @& SSLConnection) : IO Unit

-- ============================================================
-- SSL mode for connection configuration
-- ============================================================

/-- SSL negotiation mode for PostgreSQL connections. -/
inductive SSLMode where
  /-- No SSL — connect using plain TCP only. -/
  | disable
  /-- Try SSL first; if the server declines, fall back to plain TCP. -/
  | prefer
  /-- Require SSL — fail if the server does not support it. -/
  | require
  deriving Repr, BEq

instance : ToString SSLMode where
  toString
    | .disable => "disable"
    | .prefer  => "prefer"
    | .require => "require"

-- ============================================================
-- PostgreSQL SSLRequest wire protocol message
-- ============================================================

/--
  The SSLRequest message is a special PostgreSQL startup message used to
  negotiate SSL/TLS. It consists of exactly 8 bytes:
  - Int32: message length (8)
  - Int32: SSL request code (80877103)

  The server responds with a single byte:
  - 'S' (0x53): SSL accepted, proceed with TLS handshake
  - 'N' (0x4E): SSL not supported, continue with plain connection
-/
def sslRequestMessage : ByteArray :=
  LeanPQ.ByteUtils.putUInt32BE (LeanPQ.ByteUtils.putUInt32BE ByteArray.empty 8) 80877103

/-- Check if a server response byte indicates SSL acceptance. -/
def isSSLAccepted (response : UInt8) : Bool :=
  response == 'S'.val.toUInt8

end LeanPQ.SSL
