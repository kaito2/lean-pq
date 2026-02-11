namespace LeanPQ

/-- Convert a PostgreSQL text-format value to a Lean type. -/
class FromPg (α : Type) where
  fromPg : String → Option α

/-- Convert a Lean value to a PostgreSQL text-format parameter. -/
class ToPg (α : Type) where
  toPg : α → String

-- String: identity
instance : FromPg String where fromPg s := some s
instance : ToPg String where toPg s := s

-- Nat
instance : FromPg Nat where fromPg s := s.toNat?
instance : ToPg Nat where toPg := toString

-- Int
instance : FromPg Int where fromPg s := s.toInt?
instance : ToPg Int where toPg := toString

-- Bool (PostgreSQL sends "t"/"f" in text mode)
instance : FromPg Bool where
  fromPg
    | "t" => some true
    | "f" => some false
    | "true" => some true
    | "false" => some false
    | _ => none
instance : ToPg Bool where
  toPg
    | true => "t"
    | false => "f"

-- UInt32
instance : FromPg UInt32 where
  fromPg s := s.toNat?.map (·.toUInt32)
instance : ToPg UInt32 where toPg n := toString n.toNat

-- Option (handles SQL NULL)
instance [FromPg α] : FromPg (Option α) where
  fromPg s := some (FromPg.fromPg s)

end LeanPQ
