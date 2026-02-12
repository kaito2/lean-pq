/-
  Tests/Main.lean — Unit tests for the LeanPQ PostgreSQL client library.
-/
import LeanPQ.ByteUtils
import LeanPQ.Protocol
import LeanPQ.Auth.MD5
import LeanPQ.Auth.SHA256
import LeanPQ.Auth.HMAC
import LeanPQ.Auth.Base64
import LeanPQ.Auth.SCRAM
import LeanPQ.Error

open LeanPQ.ByteUtils
open LeanPQ.Protocol

-- ============================================================
-- Simple test harness
-- ============================================================

structure TestState where
  passed : Nat := 0
  failed : Nat := 0

abbrev TestRef := IO.Ref TestState

def check (ref : TestRef) (name : String) (cond : Bool) : IO Unit := do
  if cond then
    IO.println s!"PASS: {name}"
    ref.modify fun s => { s with passed := s.passed + 1 }
  else
    IO.println s!"FAIL: {name}"
    ref.modify fun s => { s with failed := s.failed + 1 }

def checkEq [BEq α] [ToString α] (ref : TestRef) (name : String) (actual expected : α) : IO Unit := do
  if actual == expected then
    IO.println s!"PASS: {name}"
    ref.modify fun s => { s with passed := s.passed + 1 }
  else
    IO.println s!"FAIL: {name} (expected: {expected}, got: {actual})"
    ref.modify fun s => { s with failed := s.failed + 1 }

-- Helper to convert a ByteArray to a lowercase hex string
def bytesToHex (bs : ByteArray) : String := Id.run do
  let mut s := ""
  for i in [:bs.size] do
    let b := bs.get! i
    let hi := b >>> 4
    let lo := b &&& 0x0f
    s := s.push (if hi < 10 then Char.ofNat (48 + hi.toNat) else Char.ofNat (87 + hi.toNat))
    s := s.push (if lo < 10 then Char.ofNat (48 + lo.toNat) else Char.ofNat (87 + lo.toNat))
  return s

-- Helper to check if a string contains a substring
def containsSubstr (haystack needle : String) : Bool :=
  (haystack.splitOn needle).length > 1

-- ============================================================
-- ByteUtils tests
-- ============================================================

def testByteUtilsPutGetInt32BE (r : TestRef) : IO Unit := do
  -- Positive value roundtrip
  let buf := putInt32BE ByteArray.empty (42 : Int32)
  let (val, off) := getInt32BE buf 0
  checkEq r "putInt32BE/getInt32BE roundtrip positive (42)" val (42 : Int32)
  checkEq r "putInt32BE/getInt32BE offset after read" off 4

  -- Negative value roundtrip
  let buf := putInt32BE ByteArray.empty (-1 : Int32)
  let (val, _) := getInt32BE buf 0
  checkEq r "putInt32BE/getInt32BE roundtrip negative (-1)" val (-1 : Int32)

  -- Zero roundtrip
  let buf := putInt32BE ByteArray.empty (0 : Int32)
  let (val, _) := getInt32BE buf 0
  checkEq r "putInt32BE/getInt32BE roundtrip zero" val (0 : Int32)

  -- Large positive value
  let buf := putInt32BE ByteArray.empty (196608 : Int32)
  let (val, _) := getInt32BE buf 0
  checkEq r "putInt32BE/getInt32BE roundtrip (196608)" val (196608 : Int32)

def testByteUtilsPutGetUInt32BE (r : TestRef) : IO Unit := do
  -- Standard roundtrip
  let buf := putUInt32BE ByteArray.empty (12345 : UInt32)
  let (val, off) := getUInt32BE buf 0
  checkEq r "putUInt32BE/getUInt32BE roundtrip (12345)" val (12345 : UInt32)
  checkEq r "putUInt32BE/getUInt32BE offset after read" off 4

  -- Zero roundtrip
  let buf := putUInt32BE ByteArray.empty (0 : UInt32)
  let (val, _) := getUInt32BE buf 0
  checkEq r "putUInt32BE/getUInt32BE roundtrip zero" val (0 : UInt32)

  -- Max value roundtrip
  let buf := putUInt32BE ByteArray.empty (0xFFFFFFFF : UInt32)
  let (val, _) := getUInt32BE buf 0
  checkEq r "putUInt32BE/getUInt32BE roundtrip max" val (0xFFFFFFFF : UInt32)

  -- Protocol version 3.0
  let buf := putUInt32BE ByteArray.empty (196608 : UInt32)
  let (val, _) := getUInt32BE buf 0
  checkEq r "putUInt32BE/getUInt32BE roundtrip protocol version (196608)" val (196608 : UInt32)

def testByteUtilsPutGetInt16BE (r : TestRef) : IO Unit := do
  -- Positive value roundtrip
  let buf := putInt16BE ByteArray.empty (1024 : Int16)
  let (val, off) := getInt16BE buf 0
  checkEq r "putInt16BE/getInt16BE roundtrip positive (1024)" val (1024 : Int16)
  checkEq r "putInt16BE/getInt16BE offset after read" off 2

  -- Negative value roundtrip
  let buf := putInt16BE ByteArray.empty (-1 : Int16)
  let (val, _) := getInt16BE buf 0
  checkEq r "putInt16BE/getInt16BE roundtrip negative (-1)" val (-1 : Int16)

  -- Zero roundtrip
  let buf := putInt16BE ByteArray.empty (0 : Int16)
  let (val, _) := getInt16BE buf 0
  checkEq r "putInt16BE/getInt16BE roundtrip zero" val (0 : Int16)

def testByteUtilsPutGetUInt16BE (r : TestRef) : IO Unit := do
  -- Standard roundtrip
  let buf := putUInt16BE ByteArray.empty (5432 : UInt16)
  let (val, off) := getUInt16BE buf 0
  checkEq r "putUInt16BE/getUInt16BE roundtrip (5432)" val (5432 : UInt16)
  checkEq r "putUInt16BE/getUInt16BE offset after read" off 2

  -- Zero roundtrip
  let buf := putUInt16BE ByteArray.empty (0 : UInt16)
  let (val, _) := getUInt16BE buf 0
  checkEq r "putUInt16BE/getUInt16BE roundtrip zero" val (0 : UInt16)

  -- Max value roundtrip
  let buf := putUInt16BE ByteArray.empty (0xFFFF : UInt16)
  let (val, _) := getUInt16BE buf 0
  checkEq r "putUInt16BE/getUInt16BE roundtrip max" val (0xFFFF : UInt16)

def testByteUtilsPutGetCString (r : TestRef) : IO Unit := do
  -- Normal string roundtrip
  let buf := putCString ByteArray.empty "hello"
  let (val, off) := getCString buf 0
  checkEq r "putCString/getCString roundtrip (hello)" val "hello"
  checkEq r "putCString/getCString offset after 'hello'" off 6  -- 5 chars + 1 null

  -- Empty string roundtrip
  let buf := putCString ByteArray.empty ""
  let (val, off) := getCString buf 0
  checkEq r "putCString/getCString roundtrip empty string" val ""
  checkEq r "putCString/getCString offset after empty string" off 1  -- just the null byte

  -- Multiple strings in sequence
  let buf := putCString ByteArray.empty "user"
  let buf := putCString buf "postgres"
  let (val1, off1) := getCString buf 0
  let (val2, off2) := getCString buf off1
  checkEq r "putCString/getCString sequential read first" val1 "user"
  checkEq r "putCString/getCString sequential read second" val2 "postgres"
  checkEq r "putCString/getCString final offset" off2 14  -- 4+1+8+1 = 14

def testByteUtilsPutGetByte (r : TestRef) : IO Unit := do
  -- Normal byte roundtrip
  let buf := putByte ByteArray.empty (0x51 : UInt8)  -- 'Q'
  let (val, off) := getByte buf 0
  checkEq r "putByte/getByte roundtrip (0x51)" val (0x51 : UInt8)
  checkEq r "putByte/getByte offset after read" off 1

  -- Zero byte
  let buf := putByte ByteArray.empty (0 : UInt8)
  let (val, _) := getByte buf 0
  checkEq r "putByte/getByte roundtrip zero" val (0 : UInt8)

  -- Max byte
  let buf := putByte ByteArray.empty (0xFF : UInt8)
  let (val, _) := getByte buf 0
  checkEq r "putByte/getByte roundtrip max (0xFF)" val (0xFF : UInt8)

-- ============================================================
-- MD5 tests
-- ============================================================

def testMD5HexEmpty (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.md5hex ByteArray.empty
  checkEq r "md5hex empty string" result "d41d8cd98f00b204e9800998ecf8427e"

def testMD5HexAbc (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.md5hex "abc".toUTF8
  checkEq r "md5hex 'abc'" result "900150983cd24fb0d6963f7d28e17f72"

def testMD5HexHelloWorld (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.md5hex "hello world".toUTF8
  checkEq r "md5hex 'hello world'" result "5eb63bbbe01eeed093cb22bb8f5acdc3"

def testPgMD5Password (r : TestRef) : IO Unit := do
  -- Known test vector: user="user", password="password", salt=0x01020304
  let salt := ByteArray.empty |>.push 0x01 |>.push 0x02 |>.push 0x03 |>.push 0x04
  let result := LeanPQ.Auth.pgMD5Password "user" "password" salt
  -- The result should start with "md5"
  check r "pgMD5Password starts with 'md5'" (result.startsWith "md5")
  -- Length should be 3 ("md5") + 32 (hex digest) = 35
  checkEq r "pgMD5Password length" result.length 35
  -- Verify the actual computed value:
  -- Step 1: md5hex("passworduser") = md5hex of the concatenation
  let innerHex := LeanPQ.Auth.md5hex ("password".toUTF8 ++ "user".toUTF8)
  let outerHex := LeanPQ.Auth.md5hex (innerHex.toUTF8 ++ salt)
  let expected := "md5" ++ outerHex
  checkEq r "pgMD5Password computed value" result expected

-- ============================================================
-- Protocol tests — FrontendMsg.serialize
-- ============================================================

def testSerializeQuery (r : TestRef) : IO Unit := do
  let msg := FrontendMsg.query "SELECT 1"
  let bytes := msg.serialize
  -- First byte should be 'Q' (0x51)
  check r "query serialize: starts with 'Q'" (bytes.get! 0 == 0x51)
  -- Next 4 bytes are the length (big-endian UInt32) including the 4 length bytes themselves
  -- Body is "SELECT 1\0" = 9 bytes, so length = 9 + 4 = 13
  let (len, _) := getUInt32BE bytes 1
  checkEq r "query serialize: length field" len (13 : UInt32)
  -- Total message size should be 1 (tag) + 4 (length) + 9 (body) = 14
  checkEq r "query serialize: total size" bytes.size 14
  -- The body should end with a null terminator
  check r "query serialize: null terminated" (bytes.get! (bytes.size - 1) == 0)

def testSerializeTerminate (r : TestRef) : IO Unit := do
  let msg := FrontendMsg.terminate
  let bytes := msg.serialize
  -- First byte should be 'X' (0x58)
  check r "terminate serialize: starts with 'X'" (bytes.get! 0 == 0x58)
  -- Length = 4 (no body, just the 4 length bytes)
  let (len, _) := getUInt32BE bytes 1
  checkEq r "terminate serialize: length field" len (4 : UInt32)
  -- Total size: 1 (tag) + 4 (length) = 5
  checkEq r "terminate serialize: total size" bytes.size 5

def testSerializeSync (r : TestRef) : IO Unit := do
  let msg := FrontendMsg.sync
  let bytes := msg.serialize
  -- First byte should be 'S' (0x53)
  check r "sync serialize: starts with 'S'" (bytes.get! 0 == 0x53)
  -- Length = 4 (no body, just the 4 length bytes)
  let (len, _) := getUInt32BE bytes 1
  checkEq r "sync serialize: length field" len (4 : UInt32)
  -- Total size: 1 (tag) + 4 (length) = 5
  checkEq r "sync serialize: total size" bytes.size 5

-- ============================================================
-- Protocol tests — BackendMsg.parse
-- ============================================================

def testParseAuthOk (r : TestRef) : IO Unit := do
  -- AuthOk: tag='R' (82), payload is UInt32 with value 0
  let payload := putUInt32BE ByteArray.empty (0 : UInt32)
  let msg := BackendMsg.parse (82 : UInt8) payload
  match msg with
  | .authOk => checkEq r "BackendMsg.parse AuthOk" "authOk" "authOk"
  | _ => check r "BackendMsg.parse AuthOk: expected authOk" false

def testParseReadyForQuery (r : TestRef) : IO Unit := do
  -- ReadyForQuery: tag='Z' (90), payload is a single byte for txStatus
  -- 'I' (73) = idle
  let payload := putByte ByteArray.empty (73 : UInt8)
  let msg := BackendMsg.parse (90 : UInt8) payload
  match msg with
  | .readyForQuery txStatus =>
    checkEq r "BackendMsg.parse ReadyForQuery txStatus" txStatus 'I'
  | _ => check r "BackendMsg.parse ReadyForQuery: expected readyForQuery" false

def testParseCommandComplete (r : TestRef) : IO Unit := do
  -- CommandComplete: tag='C' (67), payload is a CString with the command tag
  let payload := putCString ByteArray.empty "SELECT 1"
  let msg := BackendMsg.parse (67 : UInt8) payload
  match msg with
  | .commandComplete tag =>
    checkEq r "BackendMsg.parse CommandComplete tag" tag "SELECT 1"
  | _ => check r "BackendMsg.parse CommandComplete: expected commandComplete" false

-- ============================================================
-- SHA-256 tests
-- ============================================================

def testSHA256Empty (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.sha256hex ByteArray.empty
  checkEq r "sha256hex empty data" result "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

def testSHA256Abc (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.sha256hex "abc".toUTF8
  checkEq r "sha256hex 'abc'" result "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def testSHA256HelloWorld (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.sha256hex "hello world".toUTF8
  checkEq r "sha256hex 'hello world'" result "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

-- ============================================================
-- HMAC-SHA-256 tests
-- ============================================================

def testHMACSHA256KnownVector (r : TestRef) : IO Unit := do
  let key := "key".toUTF8
  let message := "The quick brown fox jumps over the lazy dog".toUTF8
  let result := LeanPQ.Auth.hmacSHA256 key message
  let resultHex := bytesToHex result
  checkEq r "hmacSHA256 key='key' msg='The quick brown fox...'"
    resultHex "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"

-- ============================================================
-- Base64 tests
-- ============================================================

def testBase64EncodeEmpty (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Encode "".toUTF8
  checkEq r "base64Encode empty" result ""

def testBase64EncodeF (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Encode "f".toUTF8
  checkEq r "base64Encode 'f'" result "Zg=="

def testBase64EncodeFo (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Encode "fo".toUTF8
  checkEq r "base64Encode 'fo'" result "Zm8="

def testBase64EncodeFoo (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Encode "foo".toUTF8
  checkEq r "base64Encode 'foo'" result "Zm9v"

def testBase64EncodeFoobar (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Encode "foobar".toUTF8
  checkEq r "base64Encode 'foobar'" result "Zm9vYmFy"

def testBase64DecodeFoo (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Decode "Zm9v"
  checkEq r "base64Decode 'Zm9v' == some 'foo'.toUTF8" result (some "foo".toUTF8)

def testBase64DecodeFoobar (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Decode "Zm9vYmFy"
  checkEq r "base64Decode 'Zm9vYmFy' == some 'foobar'.toUTF8" result (some "foobar".toUTF8)

def testBase64DecodeInvalid (r : TestRef) : IO Unit := do
  let result := LeanPQ.Auth.base64Decode "A"
  checkEq r "base64Decode 'A' == none (invalid length)" result (none : Option ByteArray)

-- ============================================================
-- SCRAM tests
-- ============================================================

def testScramClientFirstMessage (r : TestRef) : IO Unit := do
  let (msg, state) := LeanPQ.Auth.scramClientFirstMessage "user" "rOprNGfwEbeRWgbNEkqO"
  checkEq r "scramClientFirstMessage starts with 'n,,n=user,r=...'"
    msg "n,,n=user,r=rOprNGfwEbeRWgbNEkqO"
  checkEq r "scramClientFirstMessage state.clientNonce"
    state.clientNonce "rOprNGfwEbeRWgbNEkqO"
  checkEq r "scramClientFirstMessage state.clientFirstMessageBare"
    state.clientFirstMessageBare "n=user,r=rOprNGfwEbeRWgbNEkqO"

def testPbkdf2SHA256Length (r : TestRef) : IO Unit := do
  let password := "Hi There".toUTF8
  let salt := "salt".toUTF8
  let result := LeanPQ.Auth.pbkdf2SHA256 password salt 1
  -- PBKDF2-HMAC-SHA-256 always produces a 32-byte key
  checkEq r "pbkdf2SHA256 output length" result.size 32

def testScramClientFinalMessageRoundtrip (r : TestRef) : IO Unit := do
  -- Use known values adapted from RFC 5802 for SHA-256
  -- Set up client-first-message
  let (_, state) := LeanPQ.Auth.scramClientFirstMessage "user" "rOprNGfwEbeRWgbNEkqO"
  -- Simulate a server-first-message with a known server nonce, salt, and iterations
  let salt := LeanPQ.Auth.base64Encode "salty-salt-salt!!".toUTF8
  let serverFirstMessage := "r=rOprNGfwEbeRWgbNEkqOserverportion,s=" ++ salt ++ ",i=4096"
  let result := LeanPQ.Auth.scramClientFinalMessage state "pencil" serverFirstMessage
  match result with
  | some (clientFinal, serverSig) =>
    -- Verify the client-final-message starts with "c=biws" (channel binding for "n,,")
    check r "scramClientFinalMessage starts with 'c=biws'"
      (clientFinal.startsWith "c=biws")
    -- Verify it contains the server nonce
    check r "scramClientFinalMessage contains server nonce"
      (containsSubstr clientFinal "r=rOprNGfwEbeRWgbNEkqOserverportion")
    -- Verify it contains a proof
    check r "scramClientFinalMessage contains proof"
      (containsSubstr clientFinal ",p=")
    -- Server signature should be 32 bytes (SHA-256 output)
    checkEq r "scramClientFinalMessage server signature size" serverSig.size 32
  | none =>
    check r "scramClientFinalMessage should return some" false

-- ============================================================
-- Error tests
-- ============================================================

def testServerErrorFromFieldsMessageField (r : TestRef) : IO Unit := do
  let fields : List (Char × String) := [('M', "relation does not exist")]
  let err := LeanPQ.ServerError.fromFields fields
  checkEq r "ServerError.fromFields parses 'M' field" err.message "relation does not exist"

def testServerErrorFromFieldsSeverityAndCode (r : TestRef) : IO Unit := do
  let fields : List (Char × String) := [('S', "FATAL"), ('C', "42P01"), ('M', "table not found")]
  let err := LeanPQ.ServerError.fromFields fields
  checkEq r "ServerError.fromFields parses 'S' field" err.severity "FATAL"
  checkEq r "ServerError.fromFields parses 'C' field" err.code "42P01"
  checkEq r "ServerError.fromFields parses 'M' field with others" err.message "table not found"

def testPgErrorFromFields (r : TestRef) : IO Unit := do
  let fields : List (Char × String) := [('S', "ERROR"), ('C', "42601"), ('M', "syntax error")]
  let pgErr := LeanPQ.PgError.fromFields fields
  match pgErr with
  | .serverError err =>
    checkEq r "PgError.fromFields creates serverError severity" err.severity "ERROR"
    checkEq r "PgError.fromFields creates serverError message" err.message "syntax error"
  | _ => check r "PgError.fromFields should create serverError variant" false

def testPgErrorConnectionFailedToString (r : TestRef) : IO Unit := do
  let err := LeanPQ.PgError.connectionFailed "host unreachable"
  let s := toString err
  check r "PgError.connectionFailed toString contains reason"
    (containsSubstr s "host unreachable")
  check r "PgError.connectionFailed toString contains 'Connection failed'"
    (containsSubstr s "Connection failed")

-- ============================================================
-- Protocol SASL tests
-- ============================================================

def testParseAuthSASL (r : TestRef) : IO Unit := do
  -- AuthSASL: tag='R' (82), authType=10, followed by "SCRAM-SHA-256\0\0"
  let payload := putUInt32BE ByteArray.empty (10 : UInt32)
  let payload := putCString payload "SCRAM-SHA-256"
  let payload := payload.push 0  -- empty string terminator for mechanism list
  let msg := BackendMsg.parse (82 : UInt8) payload
  match msg with
  | .authSASL mechanisms =>
    checkEq r "BackendMsg.parse AuthSASL mechanism count" mechanisms.size 1
    checkEq r "BackendMsg.parse AuthSASL mechanism name" mechanisms[0]! "SCRAM-SHA-256"
  | _ => check r "BackendMsg.parse AuthSASL: expected authSASL" false

def testSerializeSaslResponse (r : TestRef) : IO Unit := do
  let responseData := "client-final-message-data".toUTF8
  let msg := FrontendMsg.saslResponse responseData
  let bytes := msg.serialize
  -- First byte should be 'p' (0x70 = 112)
  checkEq r "saslResponse serialize: tag is 'p'" (bytes.get! 0) (112 : UInt8)
  -- Length field = data.size + 4
  let (len, _) := getUInt32BE bytes 1
  checkEq r "saslResponse serialize: length field" len ((responseData.size + 4).toUInt32)
  -- Total size: 1 (tag) + 4 (length) + data.size
  checkEq r "saslResponse serialize: total size" bytes.size (1 + 4 + responseData.size)

-- ============================================================
-- Main entry point
-- ============================================================

def main : IO UInt32 := do
  IO.println "=== LeanPQ Unit Tests ==="
  IO.println ""

  let ref ← IO.mkRef ({} : TestState)

  -- ByteUtils tests
  IO.println "--- ByteUtils ---"
  testByteUtilsPutGetInt32BE ref
  testByteUtilsPutGetUInt32BE ref
  testByteUtilsPutGetInt16BE ref
  testByteUtilsPutGetUInt16BE ref
  testByteUtilsPutGetCString ref
  testByteUtilsPutGetByte ref
  IO.println ""

  -- MD5 tests
  IO.println "--- MD5 ---"
  testMD5HexEmpty ref
  testMD5HexAbc ref
  testMD5HexHelloWorld ref
  testPgMD5Password ref
  IO.println ""

  -- Protocol tests
  IO.println "--- Protocol (Frontend Serialization) ---"
  testSerializeQuery ref
  testSerializeTerminate ref
  testSerializeSync ref
  IO.println ""

  IO.println "--- Protocol (Backend Parsing) ---"
  testParseAuthOk ref
  testParseReadyForQuery ref
  testParseCommandComplete ref
  IO.println ""

  -- SHA-256 tests
  IO.println "--- SHA-256 ---"
  testSHA256Empty ref
  testSHA256Abc ref
  testSHA256HelloWorld ref
  IO.println ""

  -- HMAC-SHA-256 tests
  IO.println "--- HMAC-SHA-256 ---"
  testHMACSHA256KnownVector ref
  IO.println ""

  -- Base64 tests
  IO.println "--- Base64 ---"
  testBase64EncodeEmpty ref
  testBase64EncodeF ref
  testBase64EncodeFo ref
  testBase64EncodeFoo ref
  testBase64EncodeFoobar ref
  testBase64DecodeFoo ref
  testBase64DecodeFoobar ref
  testBase64DecodeInvalid ref
  IO.println ""

  -- SCRAM tests
  IO.println "--- SCRAM ---"
  testScramClientFirstMessage ref
  testPbkdf2SHA256Length ref
  testScramClientFinalMessageRoundtrip ref
  IO.println ""

  -- Error tests
  IO.println "--- Error ---"
  testServerErrorFromFieldsMessageField ref
  testServerErrorFromFieldsSeverityAndCode ref
  testPgErrorFromFields ref
  testPgErrorConnectionFailedToString ref
  IO.println ""

  -- Protocol SASL tests
  IO.println "--- Protocol (SASL) ---"
  testParseAuthSASL ref
  testSerializeSaslResponse ref

  let finalState ← ref.get
  IO.println ""
  IO.println "=== Summary ==="
  IO.println s!"Passed: {finalState.passed}"
  IO.println s!"Failed: {finalState.failed}"
  IO.println s!"Total:  {finalState.passed + finalState.failed}"

  if finalState.failed > 0 then
    IO.println ""
    IO.println "SOME TESTS FAILED"
    return 1
  else
    IO.println ""
    IO.println "ALL TESTS PASSED"
    return 0
