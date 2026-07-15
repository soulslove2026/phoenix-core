param(
  [Parameter(Mandatory = $false)]
  [string]$EvidenceDirectory = "D:\Phoenix Evidence\passkey-v3.7.0"
)

$ErrorActionPreference = "Stop"
$EvidenceFile = Join-Path $EvidenceDirectory "passkey_real_device.json"

if (-not (Test-Path -LiteralPath $EvidenceFile -PathType Leaf)) {
  throw "Passkey evidence file not found: $EvidenceFile"
}

$Evidence = Get-Content -LiteralPath $EvidenceFile -Raw | ConvertFrom-Json

if ($Evidence.kind -ne "passkey_real_device") {
  throw "Unexpected evidence kind. Expected passkey_real_device."
}

if ($Evidence.status -ne "passed") {
  throw "The local Passkey record is not passed; provenance reconciliation was not applied."
}

$Evidence.environment = "local"

$ReconciliationNote = "Provenance reconciled: the real-device exercise ran in local-compose and is not staging or production evidence."
$ExistingNotes = @($Evidence.notes)
if ($ExistingNotes -notcontains $ReconciliationNote) {
  $Evidence.notes = @($ExistingNotes + $ReconciliationNote)
}

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$Json = $Evidence | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText($EvidenceFile, $Json, $Utf8NoBom)

Write-Host "Reconciled local Passkey evidence provenance."
Write-Host "File: $EvidenceFile"
Write-Host "Environment: local"
Write-Host "No evidence secrets or artifact contents were displayed."
