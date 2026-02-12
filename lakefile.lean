import Lake
open Lake DSL
open System (FilePath)

package «lean-pq» where
  version := v!"0.1.0"
  moreLinkArgs := #[
    "-lssl", "-lcrypto",
    "-L/opt/homebrew/opt/openssl/lib",       -- macOS (Homebrew)
    "-L/usr/lib/x86_64-linux-gnu",           -- Linux (Ubuntu/Debian amd64)
    "-L/usr/lib/aarch64-linux-gnu"            -- Linux (Ubuntu/Debian arm64)
  ]

target ffi.o pkg : FilePath := do
  let oFile := pkg.buildDir / "ffi" / "ssl.o"
  let srcJob ← inputTextFile <| pkg.dir / "ffi" / "ssl.c"
  let leanInclude ← getLeanIncludeDir
  buildO oFile srcJob #[
    "-I" ++ leanInclude.toString,
    "-I/opt/homebrew/opt/openssl/include",    -- macOS (Homebrew)
    "-I/usr/include"                          -- Linux
  ] #["-fPIC"]

extern_lib libleanpq_ffi pkg := do
  let ffiO ← ffi.o.fetch
  let name := nameToStaticLib "leanpq_ffi"
  buildStaticLib (pkg.staticLibDir / name) #[ffiO]

lean_lib «LeanPQ» where
  srcDir := "."

lean_exe «example» where
  srcDir := "Examples"
  root := `Main

lean_exe «tests» where
  srcDir := "Tests"
  root := `Main
