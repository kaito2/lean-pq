/-
  LeanPQ.Auth.Base64 — Base64 encode/decode.
  Reference: RFC 4648
-/
namespace LeanPQ.Auth

private def base64Alphabet : String :=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

private def base64Chars : Array Char :=
  base64Alphabet.toList.toArray

private def base64EncodeChar (idx : UInt8) : Char :=
  base64Chars[idx.toNat]!

def base64Encode (data : ByteArray) : String := Id.run do
  let mut result : String := ""
  let mut i : Nat := 0
  while i + 2 < data.size do
    let b0 := data.get! i
    let b1 := data.get! (i + 1)
    let b2 := data.get! (i + 2)
    result := result.push (base64EncodeChar (b0 >>> 2))
    result := result.push (base64EncodeChar (((b0 &&& 0x03) <<< 4) ||| (b1 >>> 4)))
    result := result.push (base64EncodeChar (((b1 &&& 0x0f) <<< 2) ||| (b2 >>> 6)))
    result := result.push (base64EncodeChar (b2 &&& 0x3f))
    i := i + 3
  let remaining := data.size - i
  if remaining == 2 then
    let b0 := data.get! i
    let b1 := data.get! (i + 1)
    result := result.push (base64EncodeChar (b0 >>> 2))
    result := result.push (base64EncodeChar (((b0 &&& 0x03) <<< 4) ||| (b1 >>> 4)))
    result := result.push (base64EncodeChar ((b1 &&& 0x0f) <<< 2))
    result := result.push '='
  else if remaining == 1 then
    let b0 := data.get! i
    result := result.push (base64EncodeChar (b0 >>> 2))
    result := result.push (base64EncodeChar ((b0 &&& 0x03) <<< 4))
    result := result.push '='
    result := result.push '='
  return result

private def base64DecodeChar (c : Char) : Option UInt8 :=
  if 'A' <= c && c <= 'Z' then some (c.toNat - 'A'.toNat).toUInt8
  else if 'a' <= c && c <= 'z' then some (c.toNat - 'a'.toNat + 26).toUInt8
  else if '0' <= c && c <= '9' then some (c.toNat - '0'.toNat + 52).toUInt8
  else if c == '+' then some 62
  else if c == '/' then some 63
  else none

def base64Decode (s : String) : Option ByteArray := Id.run do
  -- Strip any whitespace and collect valid chars
  let mut chars : Array Char := #[]
  for c in s.toList do
    if c == '=' || (base64DecodeChar c).isSome then
      chars := chars.push c
  -- Length must be multiple of 4
  if chars.size % 4 != 0 then
    return none
  let mut result := ByteArray.empty
  let mut i : Nat := 0
  while i + 3 < chars.size do
    let c0 := chars[i]!
    let c1 := chars[i + 1]!
    let c2 := chars[i + 2]!
    let c3 := chars[i + 3]!
    -- Padding chars: '=' only valid in last group
    let some v0 := base64DecodeChar c0 | return none
    let some v1 := base64DecodeChar c1 | return none
    if c2 == '=' then
      -- Two padding chars: only one output byte
      if c3 != '=' then return none
      result := result.push ((v0 <<< 2) ||| (v1 >>> 4))
    else if c3 == '=' then
      -- One padding char: two output bytes
      let some v2 := base64DecodeChar c2 | return none
      result := result.push ((v0 <<< 2) ||| (v1 >>> 4))
      result := result.push ((v1 <<< 4) ||| (v2 >>> 2))
    else
      let some v2 := base64DecodeChar c2 | return none
      let some v3 := base64DecodeChar c3 | return none
      result := result.push ((v0 <<< 2) ||| (v1 >>> 4))
      result := result.push ((v1 <<< 4) ||| (v2 >>> 2))
      result := result.push ((v2 <<< 6) ||| v3)
    i := i + 4
  return some result

end LeanPQ.Auth
