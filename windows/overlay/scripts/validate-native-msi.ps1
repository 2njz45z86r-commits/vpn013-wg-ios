param([Parameter(Mandatory)][string]$MsiPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne '2njz45z86r-commits/vpn013-wg-ios') {
    throw 'MSI ICE validation is restricted to the authorized disposable GitHub-hosted Windows runner'
}
$msi=(Resolve-Path -LiteralPath $MsiPath).Path
if([IO.Path]::GetFileName($msi) -ne 'VPN013WG-1.5.7-amd64.msi') {throw 'Unexpected MSI filename for ICE validation'}
$staticPath="$msi.static-verification.json"
if(!(Test-Path -LiteralPath $staticPath -PathType Leaf)) {throw 'Static MSI verification is missing'}
$static=Get-Content -LiteralPath $staticPath -Raw | ConvertFrom-Json
$msiHash=(Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
if($static.msiSHA256 -ne $msiHash -or !$static.staticTablesPreserved -or !$static.productAndPackageCodesUnique -or !$static.cabStreamVerified -or !$static.customActionsStreamVerified -or !$static.allPayloadBytesVerified -or $static.upgradeVersion -ne '1.5.7') {
    throw 'Static MSI verification does not match the exact 1.5.7 artifact'
}

# Microsoft Msival2 syntax: Msival2 {database} {CUB file} [-l {new logfile}].
# Omitting -i runs the SDK CUB's default full ICE set; no exclusion list is used.
# https://learn.microsoft.com/en-us/windows/win32/msi/msival2-exe
$tool=$env:MSIVAL2_PATH
$cub=$env:DARICE_CUB_PATH
if(!$tool -or !$cub) {throw 'Official Windows SDK Msival2/Darice paths are not configured'}
$tool=(Resolve-Path -LiteralPath $tool).Path
$cub=(Resolve-Path -LiteralPath $cub).Path
if([IO.Path]::GetFileName($tool) -ine 'msival2.exe' -or [IO.Path]::GetFileName($cub) -ine 'darice.cub') {throw 'Expected Msival2.exe and Darice.cub from Windows SDK'}
$log=Join-Path $env:RUNNER_TEMP ('vpn013-msi-ice-'+[guid]::NewGuid().ToString('N')+'.log')
$stdout=Join-Path $env:RUNNER_TEMP ('vpn013-msi-ice-'+[guid]::NewGuid().ToString('N')+'.txt')
& $tool $msi $cub -l $log *> $stdout
$exit=$LASTEXITCODE
if($exit -ne 0) {throw "Msival2 exited with status $exit"}
if(!(Test-Path -LiteralPath $log -PathType Leaf)) {throw 'Msival2 produced no validation log'}
$logSize=(Get-Item -LiteralPath $log).Length
$outSize=(Get-Item -LiteralPath $stdout).Length
if($logSize -le 0 -or $logSize -gt 4MB -or $outSize -gt 4MB) {throw 'Msival2 validation output missing or exceeds bounded log size'}
$messages=(Get-Content -LiteralPath $log -Raw)+(Get-Content -LiteralPath $stdout -Raw)
if($messages -notmatch '(?i)ICE[0-9]{2}') {throw 'Msival2 output has no ICE evidence'}
if($messages -match '(?im)^\s*(?:ICE[0-9]{2}[^\r\n]*\b(?:ERROR|WARNING)\b|(?:ERROR|WARNING)\b[^\r\n]*)') {throw 'Msival2 reported an ICE error or warning'}
[ordered]@{msiSHA256=$msiHash;msival2SHA256=(Get-FileHash -LiteralPath $tool -Algorithm SHA256).Hash.ToLowerInvariant();dariceSHA256=(Get-FileHash -LiteralPath $cub -Algorithm SHA256).Hash.ToLowerInvariant();exitCode=$exit;iceMessagesPresent=$true;noErrorOrWarning=$true;log=$log;stdout=$stdout} | ConvertTo-Json | Set-Content -LiteralPath "$msi.ice-validation.json" -Encoding utf8
Write-Output 'PASS: full default Windows SDK Darice ICE validation, no errors or warnings'
