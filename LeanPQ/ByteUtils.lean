/-
  LeanPQ.ByteUtils — ByteArray read/write helpers for PostgreSQL wire protocol (big-endian).
-/
namespace LeanPQ.ByteUtils

-- ============================================================
-- Writing helpers
-- ============================================================

def putByte (buf : ByteArray) (b : UInt8) : ByteArray :=
  buf.push b

def putInt32BE (buf : ByteArray) (v : Int32) : ByteArray :=
  let u := v.toUInt32
  let b3 := (u >>> 24).toUInt8
  let b2 := (u >>> 16).toUInt8
  let b1 := (u >>> 8).toUInt8
  let b0 := u.toUInt8
  buf |>.push b3 |>.push b2 |>.push b1 |>.push b0

def putUInt32BE (buf : ByteArray) (v : UInt32) : ByteArray :=
  let b3 := (v >>> 24).toUInt8
  let b2 := (v >>> 16).toUInt8
  let b1 := (v >>> 8).toUInt8
  let b0 := v.toUInt8
  buf |>.push b3 |>.push b2 |>.push b1 |>.push b0

def putInt16BE (buf : ByteArray) (v : Int16) : ByteArray :=
  let u := v.toUInt16
  let b1 := (u >>> 8).toUInt8
  let b0 := u.toUInt8
  buf |>.push b1 |>.push b0

def putUInt16BE (buf : ByteArray) (v : UInt16) : ByteArray :=
  let b1 := (v >>> 8).toUInt8
  let b0 := v.toUInt8
  buf |>.push b1 |>.push b0

def putCString (buf : ByteArray) (s : String) : ByteArray :=
  let bytes := s.toUTF8
  (buf.append bytes).push 0

def putByteArray (buf : ByteArray) (data : ByteArray) : ByteArray :=
  buf.append data

-- ============================================================
-- Reading helpers (return value + new offset)
-- ============================================================

private def safeGet (buf : ByteArray) (i : Nat) : UInt8 :=
  if i < buf.size then buf.get! i else 0

def getByte (buf : ByteArray) (offset : Nat) : UInt8 × Nat :=
  (safeGet buf offset, offset + 1)

def getUInt32BE (buf : ByteArray) (offset : Nat) : UInt32 × Nat :=
  let b3 := (safeGet buf offset).toUInt32
  let b2 := (safeGet buf (offset + 1)).toUInt32
  let b1 := (safeGet buf (offset + 2)).toUInt32
  let b0 := (safeGet buf (offset + 3)).toUInt32
  ((b3 <<< 24) ||| (b2 <<< 16) ||| (b1 <<< 8) ||| b0, offset + 4)

def getInt32BE (buf : ByteArray) (offset : Nat) : Int32 × Nat :=
  let (u, off) := getUInt32BE buf offset
  (u.toInt32, off)

def getUInt16BE (buf : ByteArray) (offset : Nat) : UInt16 × Nat :=
  let b1 := (safeGet buf offset).toUInt16
  let b0 := (safeGet buf (offset + 1)).toUInt16
  ((b1 <<< 8) ||| b0, offset + 2)

def getInt16BE (buf : ByteArray) (offset : Nat) : Int16 × Nat :=
  let (u, off) := getUInt16BE buf offset
  (u.toInt16, off)

def getCString (buf : ByteArray) (offset : Nat) : String × Nat :=
  let rec loop (i : Nat) (fuel : Nat) : Nat :=
    match fuel with
    | 0 => i
    | fuel + 1 =>
      if i >= buf.size then i
      else if buf.get! i == 0 then i
      else loop (i + 1) fuel
  let endPos := loop offset (buf.size - offset + 1)
  let slice := buf.extract offset endPos
  let s := String.fromUTF8! slice
  (s, endPos + 1)

def getBytes (buf : ByteArray) (offset : Nat) (len : Nat) : ByteArray × Nat :=
  let slice := buf.extract offset (offset + len)
  (slice, offset + len)

end LeanPQ.ByteUtils
