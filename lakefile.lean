import Lake
open Lake DSL
open System (FilePath)

package «lean-pq» where
  version := v!"0.2.0"

require «lean-tls» from git
  "https://github.com/kaito2/lean-tls" @ "v0.3.1"

lean_lib «LeanPQ» where
  srcDir := "."

lean_exe «example» where
  srcDir := "Examples"
  root := `Main

lean_exe «tests» where
  srcDir := "Tests"
  root := `Main
