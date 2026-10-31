$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne '2njz45z86r-commits/vpn013-wg-ios') {
  throw 'Native fixture checks are restricted to the disposable authorized runner'
}
$projectRoot=Split-Path $PSScriptRoot -Parent
$previewExe=Join-Path $env:RUNNER_TEMP 'VPN013-Preview.exe'
& (Join-Path $projectRoot '.deps/go/bin/go.exe') build -mod=vendor -tags 'load_wgnt_from_rsrc,r013preview' -ldflags '-H windowsgui' -trimpath -buildvcs=false -o $previewExe .
if ($LASTEXITCODE -ne 0) {throw 'Native UI fixture build failed'}
foreach($scenario in @('manual-no-stats','auto','auto-no-stats','update-offer','power','traffic','services')) {
  $env:VPN013_PREVIEW_SCENARIO=$scenario
  $env:VPN013_PREVIEW_VERIFY=Join-Path $env:RUNNER_TEMP ('r013-ui-'+$scenario+'.json')
  $process=Start-Process -FilePath $previewExe -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
  if (!$process.WaitForExit(30000)) {
    $process.Kill()
    throw "Native UI fixture timed out: $scenario"
  }
  if (!(Test-Path -LiteralPath $env:VPN013_PREVIEW_VERIFY)) {throw "Missing UI report: $scenario"}
  $report=Get-Content -LiteralPath $env:VPN013_PREVIEW_VERIFY -Raw | ConvertFrom-Json
  if ($process.ExitCode -ne 0 -or !$report.passed) {throw "Native UI fixture failed $scenario : $($report.failure)"}
  $expectedChecks=5
  if ($scenario -eq 'auto-no-stats') {$expectedChecks=3}
  if ($scenario -eq 'update-offer') {$expectedChecks=6}
  if ($scenario -eq 'power') {$expectedChecks=10}
  if ($scenario -eq 'traffic') {$expectedChecks=8}
  if ($scenario -eq 'services') {$expectedChecks=8}
  if ($report.checks.Count -ne $expectedChecks -or $report.actualLoopbackEcho -ne ($scenario -notin @('auto-no-stats','update-offer','power','traffic','services'))) {throw "Incomplete native UI proof: $scenario"}
  if ($scenario -eq 'services') {
    $capture=Join-Path $env:RUNNER_TEMP 'r013-services.png'
    if (!(Test-Path -LiteralPath $capture) -or (Get-Item -LiteralPath $capture).Length -lt 1000) {throw 'Required native service chooser capture missing'}
  }
  if ($scenario -eq 'traffic') {
    $capture=Join-Path $env:RUNNER_TEMP 'r013-traffic-adaptive.png'
    if (!(Test-Path -LiteralPath $capture) -or (Get-Item -LiteralPath $capture).Length -lt 1000) {throw 'Required native adaptive traffic capture missing'}
  }
  if ($scenario -eq 'power') {
    foreach($name in @('connected','disconnected','auto','minimum-window')) {
      $capture=Join-Path $env:RUNNER_TEMP ("r013-power-$name.png")
      if (!(Test-Path -LiteralPath $capture) -or (Get-Item -LiteralPath $capture).Length -lt 1000) {throw 'Required native power capture missing'}
    }
  }
  $report | ConvertTo-Json -Depth 6
}
Remove-Item Env:VPN013_PREVIEW_VERIFY,Env:VPN013_PREVIEW_SCENARIO
