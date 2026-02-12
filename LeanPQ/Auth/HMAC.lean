/-
  LeanPQ.Auth.HMAC — HMAC-SHA-256 implementation.
  Reference: RFC 2104
-/
import LeanPQ.Auth.SHA256

namespace LeanPQ.Auth

private def hmacBlockSize : Nat := 64

def hmacSHA256 (key : ByteArray) (message : ByteArray) : ByteArray :=
  -- If key > block size, hash it
  let key' := if key.size > hmacBlockSize then sha256 key else key
  -- Pad key to block size
  let paddedKey : ByteArray := Id.run do
    let mut k := key'
    for _ in [:hmacBlockSize - k.size] do
      k := k.push 0
    return k
  -- ipad = key XOR 0x36
  let ipad : ByteArray := Id.run do
    let mut buf := ByteArray.empty
    for i in [:hmacBlockSize] do
      buf := buf.push (paddedKey.get! i ^^^ 0x36)
    return buf
  -- opad = key XOR 0x5c
  let opad : ByteArray := Id.run do
    let mut buf := ByteArray.empty
    for i in [:hmacBlockSize] do
      buf := buf.push (paddedKey.get! i ^^^ 0x5c)
    return buf
  -- HMAC = SHA-256(opad ++ SHA-256(ipad ++ message))
  sha256 (opad ++ sha256 (ipad ++ message))

end LeanPQ.Auth
