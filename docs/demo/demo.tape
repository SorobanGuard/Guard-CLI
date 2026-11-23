# VHS tape for the README terminal demo.
#
# Reproduce with:
#   vhs docs/demo/demo.tape
#
# This renders docs/demo/demo.svg (kept under 100 KB) by scanning the
# bundled examples/all-findings fixture. Requires `vhs` and a built
# `cargo-scout` binary on PATH (e.g. `cargo install --path .`).

Output docs/demo/demo.svg

Set Shell "bash"
Set FontSize 16
Set Width 1000
Set Height 560
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 60ms

# Start from a clean prompt.
Hide
Type "clear"
Enter
Show

Type "cargo scout scan examples/all-findings"
Enter
Sleep 4s

# Give viewers a moment to read the findings before the loop ends.
Sleep 2s
