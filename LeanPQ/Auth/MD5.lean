/-
  LeanPQ.Auth.MD5 — Pure Lean 4 MD5 implementation for PostgreSQL authentication.
  Reference: RFC 1321
-/
namespace LeanPQ.Auth

private def md5T : Array UInt32 := #[
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
]

private def md5S : Array UInt32 := #[
  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

private def rotateLeft (x : UInt32) (n : UInt32) : UInt32 :=
  (x <<< n) ||| (x >>> (32 - n))

private def leWord32 (buf : ByteArray) (offset : Nat) : UInt32 :=
  let b0 := if offset < buf.size then (buf.get! offset).toUInt32 else 0
  let b1 := if offset + 1 < buf.size then (buf.get! (offset + 1)).toUInt32 else 0
  let b2 := if offset + 2 < buf.size then (buf.get! (offset + 2)).toUInt32 else 0
  let b3 := if offset + 3 < buf.size then (buf.get! (offset + 3)).toUInt32 else 0
  b0 ||| (b1 <<< 8) ||| (b2 <<< 16) ||| (b3 <<< 24)

private def word32ToLE (v : UInt32) : ByteArray :=
  ByteArray.empty
    |>.push v.toUInt8
    |>.push (v >>> 8).toUInt8
    |>.push (v >>> 16).toUInt8
    |>.push (v >>> 24).toUInt8

private def md5Pad (data : ByteArray) : ByteArray :=
  let bitLen : UInt64 := (data.size.toUInt64) * 8
  -- Append 0x80
  let buf := data.push 0x80
  -- Pad with zeros until length ≡ 56 (mod 64)
  let rem := buf.size % 64
  let padLen := if rem <= 56 then 56 - rem else 64 - rem + 56
  let buf := Id.run do
    let mut b := buf
    for _ in [:padLen] do
      b := b.push 0
    return b
  -- Append 64-bit little-endian bit count
  let buf := buf
    |>.push (bitLen.toUInt8)
    |>.push ((bitLen >>> 8).toUInt8)
    |>.push ((bitLen >>> 16).toUInt8)
    |>.push ((bitLen >>> 24).toUInt8)
    |>.push ((bitLen >>> 32).toUInt8)
    |>.push ((bitLen >>> 40).toUInt8)
    |>.push ((bitLen >>> 48).toUInt8)
    |>.push ((bitLen >>> 56).toUInt8)
  buf

private structure MD5State where
  a : UInt32
  b : UInt32
  c : UInt32
  d : UInt32

private def md5Init : MD5State :=
  { a := 0x67452301, b := 0xefcdab89, c := 0x98badcfe, d := 0x10325476 }

private def md5ProcessBlock (state : MD5State) (block : ByteArray) (blockOffset : Nat) : MD5State :=
  -- Read 16 little-endian 32-bit words
  let m : Array UInt32 := Id.run do
    let mut arr := #[]
    for i in [:16] do
      arr := arr.push (leWord32 block (blockOffset + i * 4))
    return arr
  -- 64 rounds
  let (a, b, c, d) := Id.run do
    let mut a := state.a
    let mut b := state.b
    let mut c := state.c
    let mut d := state.d
    for i in [:64] do
      let (f, g) :=
        if i < 16 then
          ((b &&& c) ||| ((~~~b) &&& d), i)
        else if i < 32 then
          ((d &&& b) ||| ((~~~d) &&& c), (5 * i + 1) % 16)
        else if i < 48 then
          (b ^^^ c ^^^ d, (3 * i + 5) % 16)
        else
          (c ^^^ (b ||| (~~~d)), (7 * i) % 16)
      let temp := a + f + md5T[i]! + m[g]!
      a := d
      d := c
      c := b
      b := b + rotateLeft temp md5S[i]!
    return (a, b, c, d)
  { a := state.a + a, b := state.b + b, c := state.c + c, d := state.d + d }

def md5 (data : ByteArray) : ByteArray :=
  let padded := md5Pad data
  let numBlocks := padded.size / 64
  let state := Id.run do
    let mut st := md5Init
    for i in [:numBlocks] do
      st := md5ProcessBlock st padded (i * 64)
    return st
  word32ToLE state.a ++ word32ToLE state.b ++ word32ToLE state.c ++ word32ToLE state.d

private def hexDigit (n : UInt8) : Char :=
  if n < 10 then Char.ofNat (48 + n.toNat)  -- '0' + n
  else Char.ofNat (87 + n.toNat)              -- 'a' + (n - 10)

def md5hex (data : ByteArray) : String :=
  let digest := md5 data
  let chars := Id.run do
    let mut s : String := ""
    for i in [:digest.size] do
      let b := digest.get! i
      s := s.push (hexDigit (b >>> 4))
      s := s.push (hexDigit (b &&& 0x0f))
    return s
  chars

def pgMD5Password (user : String) (password : String) (salt : ByteArray) : String :=
  -- Step 1: md5hex(password ++ username)
  let inner := md5hex (password.toUTF8 ++ user.toUTF8)
  -- Step 2: "md5" ++ md5hex(inner_hex ++ salt)
  let outer := md5hex (inner.toUTF8 ++ salt)
  "md5" ++ outer

end LeanPQ.Auth
