/-
  Tests/Main.lean — Unit tests for the LeanPQ PostgreSQL client library.
-/
import LeanPQ.ByteUtils
import LeanPQ.Protocol
import LeanPQ.Auth.MD5

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
