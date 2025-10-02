$hex = Get-Clipboard          # your space/newline-separated hex bytes
$key = 0x44                   # <-- set your key

# Build a true [byte[]]
$tokens = $hex -split '\s+' | Where-Object { $_ }
[byte[]]$bytes = foreach ($t in $tokens) { [Convert]::ToByte($t,16) }

function Ror([byte]$b, [int]$r){
    $r = $r -band 7
    [byte](((($b -shr $r) -bor (($b -shl (8-$r)) -band 0xFF))) -band 0xFF)
}

# XOR then ROR 1  (note the [byte] cast on the XOR result)
[byte[]]$plain = for ($i=0; $i -lt $bytes.Length; $i++) {
    Ror ([byte]($bytes[$i] -bxor $key)) 1
}

# Show ASCII (escape non-printables)
($plain | ForEach-Object {
    if (32 -le $_ -and $_ -le 126) { [char]$_ } else { '\x{0:X2}' -f $_ }
}) -join ''
