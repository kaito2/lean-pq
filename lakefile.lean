import Lake
open Lake DSL

package «lean-pq» where
  version := v!"0.1.0"

lean_lib «LeanPQ» where
  srcDir := "."

lean_exe «example» where
  srcDir := "Examples"
  root := `Main

lean_exe «tests» where
  srcDir := "Tests"
  root := `Main
