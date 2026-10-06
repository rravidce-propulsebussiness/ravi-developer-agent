param(
  [Parameter(Mandatory=$true)]
  [ValidatePattern('^[A-Za-z0-9_]{1,80}$')]
  [string]$Name
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$envPath = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envPath)) {
  throw "runner/.env is missing. Run .\setup-windows.ps1 first."
}

$key = "BROWSER_SECRET_" + $Name.ToUpperInvariant()
$secureValue = Read-Host "Enter value for $key (input is hidden)" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
try {
  $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

if ([string]::IsNullOrEmpty($value)) {
  throw "Secret value cannot be empty."
}
if ($value -match '[\r\n]') {
  throw "Multiline secret values are not supported by runner/.env."
}

$lines = @(Get-Content $envPath)
$updated = $false
for ($i = 0; $i -lt $lines.Count; $i++) {
  $line = [string]$lines[$i]
  if ($line.StartsWith($key + "=")) {
    $lines[$i] = $key + "=" + $value
    $updated = $true
  }
}
if (-not $updated) {
  $lines += $key + "=" + $value
}
$lines | Set-Content -Encoding UTF8 $envPath

Remove-Variable value -ErrorAction SilentlyContinue
Write-Host "Saved secret alias '$($Name.ToLowerInvariant())' locally in runner/.env."
Write-Host "The value was not printed. Restart .\start-windows.ps1 for the runner to load it."
