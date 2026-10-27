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
$oldMsi=Join-Path $env:RUNNER_TEMP 'VPN013WG-1.5.3-amd64.msi'
curl.exe --fail --location --silent --show-error --connect-timeout 20 --max-time 180 --output $oldMsi 'https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/windows-1.5.3/VPN013WG-1.5.3-amd64.msi'
if ($LASTEXITCODE -ne 0 -or (Get-FileHash -LiteralPath $oldMsi -Algorithm SHA256).Hash.ToLower() -ne '723a0a0666dfaeabf12fdb13288dd69b7e22c18dd72797282ef22a75a5919c3e') {throw 'Previous released MSI did not match the pinned artifact'}
# Read MSI metadata without running any custom action.
function Read-MsiProperty([string]$path,[string]$property) {
  $installer=New-Object -ComObject WindowsInstaller.Installer
  $database=$installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($path,0))
  $query="SELECT ``Value`` FROM ``Property`` WHERE ``Property``='$property'"
  $view=$database.GetType().InvokeMember('OpenView','InvokeMethod',$null,$database,@($query))
  $view.GetType().InvokeMember('Execute','InvokeMethod',$null,$view,$null) | Out-Null
  $record=$view.GetType().InvokeMember('Fetch','InvokeMethod',$null,$view,$null)
  if ($null -eq $record) {throw "Missing MSI property $property"}
  $value=$record.GetType().InvokeMember('StringData','GetProperty',$null,$record,@(1))
  $view.GetType().InvokeMember('Close','InvokeMethod',$null,$view,$null) | Out-Null
  foreach($item in @($record,$view,$database,$installer)) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($item)}
  return $value
}
function Registered-Products {
  foreach($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
    Get-ItemProperty -Path ($root+'\*') -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -in @('VPN013','VPN013 WG','VPN013.com WG')}
  }
}
$oldCode=Read-MsiProperty $oldMsi 'ProductCode'
$newCode=Read-MsiProperty $msi 'ProductCode'
$oldUpgrade=Read-MsiProperty $oldMsi 'UpgradeCode'
$newUpgrade=Read-MsiProperty $msi 'UpgradeCode'
if ($oldUpgrade -ne $newUpgrade -or $newUpgrade.Trim('{}') -ine '7669e7d6-2d96-51ef-b972-dce59d214438' -or $oldCode -eq $newCode) {throw 'MSI update identity is not preserved'}
if ((Read-MsiProperty $oldMsi 'ProductVersion') -ne '1.5.3' -or (Read-MsiProperty $msi 'ProductVersion') -ne $releaseVersion) {throw 'Unexpected old/new MSI version'}
New-Item -ItemType Directory -Path (Split-Path $stockSentinel) -Force | Out-Null
[System.IO.File]::WriteAllText($stockSentinel,'stock app sentinel')
# Install the exact shipped version first. There is intentionally NO uninstall
# between old and new: this exercises Windows Installer MajorUpgrade itself.
$process=Start-Process msiexec.exe -ArgumentList @('/i',('"'+$oldMsi+'"'),'/qn','/norestart','DO_NOT_LAUNCH=1') -Wait -PassThru -WindowStyle Hidden
if ($process.ExitCode -notin @(0,3010)) {throw 'Previous released MSI install failed'}
$oldProducts=@(Registered-Products)
if ($oldProducts.Count -ne 1 -or $oldProducts[0].DisplayVersion -ne '1.5.3') {throw 'Previous installation registration missing'}
$dataSentinel=Join-Path $installRoot 'Data\vpn013-ci-preserve.txt'
New-Item -ItemType Directory -Path (Split-Path $dataSentinel) -Force | Out-Null
[System.IO.File]::WriteAllText($dataSentinel,'owned data sentinel')
# Synthetic DPAPI data only. No customer profile, account, or signing material.
$privateSentinel=Join-Path $installRoot 'Data\vpn013-ci-private.bin'
$plain=[Text.Encoding]::UTF8.GetBytes('{"orderID":"ci-existing-order","profileID":"ci-existing-profile","key":"synthetic-only","expiry":1893456000000}')
$encrypted=[Security.Cryptography.ProtectedData]::Protect($plain,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
[IO.File]::WriteAllBytes($privateSentinel,$encrypted)
$privateHash=(Get-FileHash -LiteralPath $privateSentinel -Algorithm SHA256).Hash
$process=Start-Process msiexec.exe -ArgumentList @('/i',('"'+$msi+'"'),'/qn','/norestart','DO_NOT_LAUNCH=1','/l*v',('"'+(Join-Path $env:RUNNER_TEMP 'vpn013-install.log')+'"')) -Wait -PassThru -WindowStyle Hidden
if ($process.ExitCode -notin @(0,3010)) {throw "MSI install failed: $($process.ExitCode)"}
if (!(Test-Path -LiteralPath (Join-Path $installRoot 'VPN013WG.exe'))) {throw 'Installed binary missing'}
if (!(Test-Path -LiteralPath (Join-Path $installRoot 'THIRD-PARTY-NOTICES.txt'))) {throw 'Installed notices missing'}
$products=@(Registered-Products)
if ($products.Count -ne 1 -or $products[0].DisplayName -ne 'VPN013' -or $products[0].DisplayVersion -ne $releaseVersion -or $products[0].PSChildName -ine $newCode) {throw 'Upgrade left duplicate or old product registration'}
if ([Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $installRoot 'VPN013WG.exe')).ProductVersion -ne $releaseVersion) {throw 'Installed executable version mismatch'}
function Assert-PreservedData {
  if ([IO.File]::ReadAllText($dataSentinel) -ne 'owned data sentinel' -or (Get-FileHash -LiteralPath $privateSentinel -Algorithm SHA256).Hash -ne $privateHash) {throw 'Existing data bytes changed'}
  $decoded=[Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($privateSentinel),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
  if ([Convert]::ToBase64String($decoded) -ne [Convert]::ToBase64String($plain)) {throw 'Existing protected data no longer decrypts'}
}
Assert-PreservedData
[ordered]@{from='1.5.3';to=$releaseVersion;oldMSISHA256='723a0a0666dfaeabf12fdb13288dd69b7e22c18dd72797282ef22a75a5919c3e';sameUpgradeCode=$true;singleInstalledProduct=$true;withoutUninstall=$true;existingDataBytesPreserved=$true;syntheticDPAPIDecrypts=$true;customerDataUsed=$false;hostedRunnerOnly=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:RUNNER_TEMP 'r013-in-place-upgrade.json') -Encoding utf8
try {
  & (Join-Path $projectRoot '.deps\go\bin\go.exe') run -mod=vendor (Join-Path $PSScriptRoot 'ci-vpn-smoke.go')
  if ($LASTEXITCODE -ne 0) {throw 'Native VPN smoke test failed'}
  $repairLog=Join-Path $env:RUNNER_TEMP 'vpn013-repair.log'
  $process=Start-Process msiexec.exe -ArgumentList @('/fa',('"'+$msi+'"'),'/qn','/norestart','DO_NOT_LAUNCH=1','/l*v',('"'+$repairLog+'"')) -Wait -PassThru -WindowStyle Hidden
  if ($process.ExitCode -notin @(0,3010)) {
    Get-Content -LiteralPath $repairLog | Select-String -Pattern 'Return value 3|[Ee]rror|[Ff]ailed' -Context 2,2 | Select-Object -Last 35 | ForEach-Object { $_.ToString() }
    throw "MSI repair failed: $($process.ExitCode)"
  }
  Assert-PreservedData
} finally {
  $process=Start-Process msiexec.exe -ArgumentList @('/x',('"'+$msi+'"'),'/qn','/norestart','DO_NOT_LAUNCH=1') -Wait -PassThru -WindowStyle Hidden
  if ($process.ExitCode -notin @(0,3010)) {throw 'MSI uninstall failed'}
}
Assert-PreservedData
if ([System.IO.File]::ReadAllText($stockSentinel) -ne 'stock app sentinel') {throw 'Installer changed stock app data'}
if (Get-Service -Name 'VPN013WGTunnel$R013CISmoke' -ErrorAction SilentlyContinue) {throw 'Synthetic tunnel service was not removed'}
Write-Output 'PASS: exact released1.5.3 in-place upgrade, one installed product, DPAPI/data preservation, native VPN test, repair, uninstall, and stock preservation'
