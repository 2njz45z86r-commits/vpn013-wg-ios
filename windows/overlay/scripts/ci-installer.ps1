$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne '2njz45z86r-commits/vpn013-wg-ios') {
  throw 'Installation tests are restricted to the authorized disposable GitHub-hosted runner'
}
$projectRoot=Split-Path $PSScriptRoot -Parent
$versionSource=Get-Content -LiteralPath (Join-Path $projectRoot 'version/version.go') -Raw
if ($versionSource -notmatch 'Number\s*=\s*"([\d.]+)"') {throw 'Missing application version'}
$releaseVersion=$Matches[1]
$msi=Join-Path $projectRoot ("installer\dist\VPN013WG-$releaseVersion-amd64.msi")
$installRoot=Join-Path $env:ProgramFiles 'VPN013 WG'
$stockSentinel=Join-Path $env:ProgramFiles 'AmneziaWG\vpn013-ci-preserve.txt'
New-Item -ItemType Directory -Path (Split-Path $stockSentinel) -Force | Out-Null
[System.IO.File]::WriteAllText($stockSentinel,'stock app sentinel')
$process=Start-Process msiexec.exe -ArgumentList @('/i',('"'+$msi+'"'),'/qn','/norestart','DO_NOT_LAUNCH=1','/l*v',('"'+(Join-Path $env:RUNNER_TEMP 'vpn013-install.log')+'"')) -Wait -PassThru -WindowStyle Hidden
if ($process.ExitCode -notin @(0,3010)) {throw "MSI install failed: $($process.ExitCode)"}
if (!(Test-Path -LiteralPath (Join-Path $installRoot 'VPN013WG.exe'))) {throw 'Installed binary missing'}
if (!(Test-Path -LiteralPath (Join-Path $installRoot 'THIRD-PARTY-NOTICES.txt'))) {throw 'Installed notices missing'}
$dataSentinel=Join-Path $installRoot 'Data\vpn013-ci-preserve.txt'
New-Item -ItemType Directory -Path (Split-Path $dataSentinel) -Force | Out-Null
[System.IO.File]::WriteAllText($dataSentinel,'owned data sentinel')
try {
  & (Join-Path $projectRoot '.deps\go\bin\go.exe') run -mod=vendor (Join-Path $PSScriptRoot 'ci-vpn-smoke.go')
  if ($LASTEXITCODE -ne 0) {throw 'Native VPN smoke test failed'}
  $repairLog=Join-Path $env:RUNNER_TEMP 'vpn013-repair.log'
  $process=Start-Process msiexec.exe -ArgumentList @('/fa',('"'+$msi+'"'),'/qn','/norestart','DO_NOT_LAUNCH=1','/l*v',('"'+$repairLog+'"')) -Wait -PassThru -WindowStyle Hidden
  if ($process.ExitCode -notin @(0,3010)) {
    Get-Content -LiteralPath $repairLog | Select-String -Pattern 'Return value 3|[Ee]rror|[Ff]ailed' -Context 2,2 | Select-Object -Last 35 | ForEach-Object { $_.ToString() }
    throw "MSI repair failed: $($process.ExitCode)"
  }
  if ([System.IO.File]::ReadAllText($dataSentinel) -ne 'owned data sentinel') {throw 'Repair changed existing data'}
} finally {
  $process=Start-Process msiexec.exe -ArgumentList @('/x',('"'+$msi+'"'),'/qn','/norestart','DO_NOT_LAUNCH=1') -Wait -PassThru -WindowStyle Hidden
  if ($process.ExitCode -notin @(0,3010)) {throw 'MSI uninstall failed'}
}
if ([System.IO.File]::ReadAllText($dataSentinel) -ne 'owned data sentinel') {throw 'Uninstall removed existing data'}
if ([System.IO.File]::ReadAllText($stockSentinel) -ne 'stock app sentinel') {throw 'Installer changed stock app data'}
if (Get-Service -Name 'VPN013WGTunnel$R013CISmoke' -ErrorAction SilentlyContinue) {throw 'Synthetic tunnel service was not removed'}
Write-Output 'PASS: install, native VPN test, repair, uninstall, and data/stock preservation'
