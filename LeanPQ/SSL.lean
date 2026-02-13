/-
  LeanPQ.SSL — SSL/TLS types and wire protocol helpers for PostgreSQL connections.

  This module provides:
  - SSLMode enumeration for connection configuration
  - The SSLRequest wire protocol message for PostgreSQL SSL negotiation
-/
import LeanPQ.ByteUtils

namespace LeanPQ.SSL

-- ============================================================
-- SSL mode for connection configuration
-- ============================================================

/-- SSL negotiation mode for PostgreSQL connections. -/
inductive SSLMode where
  /-- No SSL — connect using plain TCP only. -/
  | disable
  /-- Try SSL first; if the server declines, fall back to plain TCP. -/
  | prefer
  /-- Require SSL — fail if the server does not support it.
      No certificate verification is performed. -/
  | require
  /-- Require SSL with CA certificate chain verification.
      The server certificate must be signed by a trusted CA. -/
  | verifyCA
  /-- Require SSL with CA verification and hostname verification.
      The server certificate must be signed by a trusted CA and
      its CN/SAN must match the connection hostname. -/
  | verifyFull
  deriving Repr, BEq

instance : ToString SSLMode where
  toString
    | .disable    => "disable"
    | .prefer     => "prefer"
    | .require    => "require"
    | .verifyCA   => "verify-ca"
    | .verifyFull => "verify-full"

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
