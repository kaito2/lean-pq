/-
  LeanPQ.Auth.SHA256 — Pure Lean 4 SHA-256 implementation.
  Reference: FIPS 180-4
-/
namespace LeanPQ.Auth

-- 64 round constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
private def sha256K : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

-- Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
private def sha256H0 : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

private def rotateRight (x : UInt32) (n : UInt32) : UInt32 :=
  (x >>> n) ||| (x <<< (32 - n))

private def beWord32 (buf : ByteArray) (offset : Nat) : UInt32 :=
  let b0 := if offset < buf.size then (buf.get! offset).toUInt32 else 0
  let b1 := if offset + 1 < buf.size then (buf.get! (offset + 1)).toUInt32 else 0
  let b2 := if offset + 2 < buf.size then (buf.get! (offset + 2)).toUInt32 else 0
  let b3 := if offset + 3 < buf.size then (buf.get! (offset + 3)).toUInt32 else 0
  (b0 <<< 24) ||| (b1 <<< 16) ||| (b2 <<< 8) ||| b3

private def word32ToBE (v : UInt32) : ByteArray :=
  ByteArray.empty
    |>.push (v >>> 24).toUInt8
    |>.push (v >>> 16).toUInt8
    |>.push (v >>> 8).toUInt8
    |>.push v.toUInt8

private def sha256Pad (data : ByteArray) : ByteArray :=
  let bitLen : UInt64 := (data.size.toUInt64) * 8
  -- Append 0x80
  let buf := data.push 0x80
  -- Pad with zeros until length = 56 (mod 64)
  let rem := buf.size % 64
  let padLen := if rem <= 56 then 56 - rem else 64 - rem + 56
  let buf := Id.run do
    let mut b := buf
    for _ in [:padLen] do
      b := b.push 0
    return b
  -- Append 64-bit big-endian bit count
  let buf := buf
    |>.push ((bitLen >>> 56).toUInt8)
    |>.push ((bitLen >>> 48).toUInt8)
    |>.push ((bitLen >>> 40).toUInt8)
    |>.push ((bitLen >>> 32).toUInt8)
    |>.push ((bitLen >>> 24).toUInt8)
    |>.push ((bitLen >>> 16).toUInt8)
    |>.push ((bitLen >>> 8).toUInt8)
    |>.push (bitLen.toUInt8)
  buf

private structure SHA256State where
  h0 : UInt32
  h1 : UInt32
  h2 : UInt32
  h3 : UInt32
  h4 : UInt32
  h5 : UInt32
  h6 : UInt32
  h7 : UInt32

private def sha256Init : SHA256State :=
  { h0 := sha256H0[0]!, h1 := sha256H0[1]!, h2 := sha256H0[2]!, h3 := sha256H0[3]!,
    h4 := sha256H0[4]!, h5 := sha256H0[5]!, h6 := sha256H0[6]!, h7 := sha256H0[7]! }

private def sha256ProcessBlock (state : SHA256State) (block : ByteArray) (blockOffset : Nat) : SHA256State :=
  -- Prepare message schedule W[0..63]
  let w : Array UInt32 := Id.run do
    let mut arr : Array UInt32 := #[]
    -- W[0..15] from block
    for i in [:16] do
      arr := arr.push (beWord32 block (blockOffset + i * 4))
    -- W[16..63] derived
    for i in [16:64] do
      let s0 := rotateRight arr[i - 15]! 7 ^^^ rotateRight arr[i - 15]! 18 ^^^ (arr[i - 15]! >>> 3)
      let s1 := rotateRight arr[i - 2]! 17 ^^^ rotateRight arr[i - 2]! 19 ^^^ (arr[i - 2]! >>> 10)
      arr := arr.push (arr[i - 16]! + s0 + arr[i - 7]! + s1)
    return arr
  -- Compression: 64 rounds
  let (a, b, c, d, e, f, g, h) := Id.run do
    let mut a := state.h0
    let mut b := state.h1
    let mut c := state.h2
    let mut d := state.h3
    let mut e := state.h4
    let mut f := state.h5
    let mut g := state.h6
    let mut h := state.h7
    for i in [:64] do
      let s1 := rotateRight e 6 ^^^ rotateRight e 11 ^^^ rotateRight e 25
      let ch := (e &&& f) ^^^ ((~~~e) &&& g)
      let temp1 := h + s1 + ch + sha256K[i]! + w[i]!
      let s0 := rotateRight a 2 ^^^ rotateRight a 13 ^^^ rotateRight a 22
      let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
      let temp2 := s0 + maj
      h := g
      g := f
      f := e
      e := d + temp1
      d := c
      c := b
      b := a
      a := temp1 + temp2
    return (a, b, c, d, e, f, g, h)
  { h0 := state.h0 + a, h1 := state.h1 + b, h2 := state.h2 + c, h3 := state.h3 + d,
    h4 := state.h4 + e, h5 := state.h5 + f, h6 := state.h6 + g, h7 := state.h7 + h }

def sha256 (data : ByteArray) : ByteArray :=
  let padded := sha256Pad data
  let numBlocks := padded.size / 64
  let state := Id.run do
    let mut st := sha256Init
    for i in [:numBlocks] do
      st := sha256ProcessBlock st padded (i * 64)
    return st
  word32ToBE state.h0 ++ word32ToBE state.h1 ++ word32ToBE state.h2 ++ word32ToBE state.h3 ++
  word32ToBE state.h4 ++ word32ToBE state.h5 ++ word32ToBE state.h6 ++ word32ToBE state.h7

private def hexDigit (n : UInt8) : Char :=
  if n < 10 then Char.ofNat (48 + n.toNat)  -- '0' + n
  else Char.ofNat (87 + n.toNat)              -- 'a' + (n - 10)

def sha256hex (data : ByteArray) : String :=
  let digest := sha256 data
  let chars := Id.run do
    let mut s : String := ""
    for i in [:digest.size] do
      let b := digest.get! i
      s := s.push (hexDigit (b >>> 4))
      s := s.push (hexDigit (b &&& 0x0f))
    return s
  chars

end LeanPQ.Auth
