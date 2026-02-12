/-
  LeanPQ.Auth.SCRAM — SCRAM-SHA-256 client implementation for PostgreSQL authentication.
  Reference: RFC 5802
-/
import LeanPQ.Auth.SHA256
import LeanPQ.Auth.HMAC
import LeanPQ.Auth.Base64

namespace LeanPQ.Auth

structure ScramState where
  clientNonce : String
  clientFirstMessageBare : String

/-- XOR two ByteArrays of equal length. -/
private def xorBytes (a b : ByteArray) : ByteArray := Id.run do
  let len := min a.size b.size
  let mut result := ByteArray.empty
  for i in [:len] do
    result := result.push (a.get! i ^^^ b.get! i)
  return result

/-- PBKDF2-HMAC-SHA-256 with dkLen = 32 (one block). -/
def pbkdf2SHA256 (password : ByteArray) (salt : ByteArray) (iterations : Nat) : ByteArray :=
  -- U1 = HMAC(password, salt ++ INT(1))
  -- INT(1) = 0x00000001 (4 bytes big-endian)
  let saltWithIndex := salt |>.push 0 |>.push 0 |>.push 0 |>.push 1
  let u1 := hmacSHA256 password saltWithIndex
  -- Iteratively compute U2 .. Ui, XOR all together
  let (result, _) := Id.run do
    let mut acc := u1
    let mut prev := u1
    for _ in [1:iterations] do
      let ui := hmacSHA256 password prev
      acc := xorBytes acc ui
      prev := ui
    return (acc, prev)
  result

/-- Parse a key=value pair from a SCRAM message attribute. -/
private def parseScramAttr (s : String) (key : Char) : Option String :=
  -- Search for key= at start or after comma
  let parts := s.splitOn ","
  Id.run do
    for part in parts do
      let chars := part.toList
      match chars with
      | k :: '=' :: rest => if k == key then return some (String.ofList rest)
      | _ => pure ()
    return none

/-- Create client-first-message and initial SCRAM state. -/
def scramClientFirstMessage (user : String) (nonce : String) : String × ScramState :=
  let bare := "n=" ++ user ++ ",r=" ++ nonce
  let msg := "n,," ++ bare
  (msg, { clientNonce := nonce, clientFirstMessageBare := bare })

/-- Parse server-first-message and create client-final-message.
    Returns (client-final-message, expected-server-signature) on success. -/
def scramClientFinalMessage (state : ScramState) (password : String) (serverFirstMessage : String)
    : Option (String × ByteArray) := do
  -- Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
  let serverNonce ← parseScramAttr serverFirstMessage 'r'
  let saltB64 ← parseScramAttr serverFirstMessage 's'
  let iterStr ← parseScramAttr serverFirstMessage 'i'
  let salt ← base64Decode saltB64
  let iterations := iterStr.toNat!
  if iterations == 0 then failure
  -- Verify server nonce starts with client nonce
  if !serverNonce.startsWith state.clientNonce then failure
  -- Key derivation
  let saltedPassword := pbkdf2SHA256 password.toUTF8 salt iterations
  let clientKey := hmacSHA256 saltedPassword "Client Key".toUTF8
  let storedKey := sha256 clientKey
  let serverKey := hmacSHA256 saltedPassword "Server Key".toUTF8
  -- client-final-message-without-proof
  let channelBinding := base64Encode "n,,".toUTF8  -- "biws"
  let clientFinalWithoutProof := "c=" ++ channelBinding ++ ",r=" ++ serverNonce
  -- AuthMessage
  let authMessage := state.clientFirstMessageBare ++ "," ++ serverFirstMessage ++ "," ++ clientFinalWithoutProof
  let clientSignature := hmacSHA256 storedKey authMessage.toUTF8
  let clientProof := xorBytes clientKey clientSignature
  let serverSignature := hmacSHA256 serverKey authMessage.toUTF8
  -- client-final-message
  let proofB64 := base64Encode clientProof
  let clientFinalMessage := clientFinalWithoutProof ++ ",p=" ++ proofB64
  return (clientFinalMessage, serverSignature)

/-- Verify server-final-message against expected server signature. -/
def scramVerifyServerFinal (serverFinalMessage : String) (expectedSignature : ByteArray) : Bool :=
  match parseScramAttr serverFinalMessage 'v' with
  | none => false
  | some sigB64 =>
    match base64Decode sigB64 with
    | none => false
    | some sig => sig == expectedSignature

end LeanPQ.Auth
