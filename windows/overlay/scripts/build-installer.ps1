$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne '2njz45z86r-commits/vpn013-wg-ios' -or $env:GITHUB_SHA -notmatch '^[0-9a-fA-F]{40}$') {
  throw 'Release installer build requires the authorized GitHub-hosted Windows runner and exact commit'
}
$projectRoot=Split-Path $PSScriptRoot -Parent
$versionSource=Get-Content -LiteralPath (Join-Path $projectRoot 'version/version.go') -Raw
if ($versionSource -notmatch 'Number\s*=\s*"([\d.]+)"') {throw 'Missing application version'}
$releaseVersion=$Matches[1]
if ($releaseVersion -ne '1.5.7') {throw 'Native MSI builder is pinned to Windows 1.5.7'}
Set-Location -LiteralPath $projectRoot
$env:PATH="$projectRoot\.deps\llvm-mingw-20231128-ucrt-x86_64\bin;$projectRoot\.deps;$env:PATH"
$driver="$projectRoot\.deps\official-extracted\AmneziaWG\wintun.dll"
if ((Get-FileHash -LiteralPath $driver -Algorithm SHA256).Hash.ToLower() -ne 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce') {throw 'Driver SHA256 mismatch'}
if ((Get-AuthenticodeSignature -LiteralPath $driver).Status -ne 'Valid') {throw 'Driver Authenticode invalid'}
Copy-Item -LiteralPath $driver -Destination amd64\wintun.dll -Force
$toolsHeaderPath="$projectRoot\.deps\src\ipc-uapi-windows.h"
$toolsSource=[System.IO.File]::ReadAllText($toolsHeaderPath)
$toolsSource=$toolsSource.Replace('Administrators\\AmneziaWG\\','Administrators\\VPN013WG\\')
if ($toolsSource.Contains('Administrators\\AmneziaWG\\') -or !$toolsSource.Contains('Administrators\\VPN013WG\\')) {throw 'Unexpected AWG tool pipe namespace'}
[System.IO.File]::WriteAllText($toolsHeaderPath,$toolsSource,[System.Text.UTF8Encoding]::new($false))
$env:PATHEXT='.exe'
& "$projectRoot\.deps\make.exe" --no-print-directory -C .deps\src PLATFORM=windows CC=x86_64-w64-mingw32-gcc WINDRES=x86_64-w64-mingw32-windres V=1 RUNSTATEDIR= SYSTEMDUNITDIR= -j2 *> .deps\tools-build.log
if ($LASTEXITCODE -ne 0) {throw 'AWG tools build failed'}
$toolsBinary="$projectRoot\.deps\src\wg.exe"
if (!(Test-Path -LiteralPath $toolsBinary)) {$toolsBinary="$projectRoot\.deps\src\wg"}
$toolsHeader=[System.IO.File]::ReadAllBytes($toolsBinary)
if ($toolsHeader[0] -ne 0x4d -or $toolsHeader[1] -ne 0x5a) {throw 'AWG tools output is not a PE executable'}
Copy-Item -LiteralPath $toolsBinary -Destination amd64\awg.exe -Force
& "$PSScriptRoot\prepare-notices.ps1"
New-Item -ItemType Directory -Path installer\amd64,installer\dist -Force | Out-Null
& x86_64-w64-mingw32-gcc -O3 -Wall -std=gnu11 -DWINVER=0x0601 -D_WIN32_WINNT=0x0601 -municode -DUNICODE -D_UNICODE -DNDEBUG -shared -s '-Wl,--kill-at' '-Wl,--major-os-version=6' '-Wl,--minor-os-version=1' '-Wl,--major-subsystem-version=6' '-Wl,--minor-subsystem-version=1' '-Wl,--tsaware' '-Wl,--dynamicbase' '-Wl,--nxcompat' '-Wl,--export-all-symbols' -o installer\amd64\customactions.dll installer\customactions.c -lmsi -lole32 -lshlwapi -lshell32 -luuid -lntdll
if ($LASTEXITCODE -ne 0) {throw 'Installer custom actions build failed'}
$template=Join-Path $projectRoot '.deps/native-installer/VPN013WG-1.5.6-amd64.msi'
& "$PSScriptRoot\bootstrap-installer.ps1"
$sourceManifestHash=(Get-FileHash -LiteralPath (Join-Path $projectRoot 'SOURCE-MANIFEST.json') -Algorithm SHA256).Hash.ToLowerInvariant()
$layoutHash=(Get-FileHash -LiteralPath (Join-Path $projectRoot 'installer/wireguard.wxs') -Algorithm SHA256).Hash.ToLowerInvariant()
$actionsHash=(Get-FileHash -LiteralPath (Join-Path $projectRoot 'installer/customactions.c') -Algorithm SHA256).Hash.ToLowerInvariant()
$msi=Join-Path $projectRoot "installer/dist/VPN013WG-$releaseVersion-amd64.msi"
& "$PSScriptRoot\build-native-msi.ps1" -TemplateMsi $template -SourceRoot $projectRoot -PayloadRoot $projectRoot -OutputMsi $msi -ExpectedSourceManifestSha256 $sourceManifestHash -ExpectedInstallerWxsSha256 $layoutHash -ExpectedCustomActionsSourceSha256 $actionsHash -GitCommit $env:GITHUB_SHA
Write-Output "Built VPN013 WG Windows installer $releaseVersion amd64; SDK ICE and native installation gates remain required"
