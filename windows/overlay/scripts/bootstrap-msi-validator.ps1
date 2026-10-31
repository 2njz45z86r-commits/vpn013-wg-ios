$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# This script may install an SDK component. Never run it on an owner workstation.
if ($env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:RUNNER_OS -cne 'Windows' -or
    $env:GITHUB_REPOSITORY -cne '2njz45z86r-commits/vpn013-wg-ios' -or
    $env:RUNNER_TEMP -notmatch '^[A-Za-z]:\\a\\_temp$' -or
    $env:RUNNER_WORKSPACE -notmatch '^[A-Za-z]:\\a\\[^\\]+$' -or
    $env:GITHUB_ENV -notmatch '^[A-Za-z]:\\a\\_temp\\_runner_file_commands\\set_env_[A-Za-z0-9_-]+$') {
    throw 'SDK MSI tool bootstrap is restricted to this repository on a disposable GitHub-hosted Windows runner'
}
if (!(Test-Path -LiteralPath $env:RUNNER_TEMP -PathType Container) -or
    !(Test-Path -LiteralPath $env:GITHUB_ENV -PathType Leaf)) {
    throw 'Hosted runner temporary directory or GITHUB_ENV is missing'
}

$kitRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$standaloneRoot = Join-Path ${env:ProgramFiles(x86)} 'MsiVal2'
$sdkVersion = '10.0.26100.7705'
$sdkUrl = 'https://download.microsoft.com/download/f4b30f2a-4fc3-430e-9b03-c842b5f5f9f1/KIT_BUNDLE_WINDOWSSDK_MEDIACREATION/winsdksetup.exe'
$sdkSha256 = '6FA0FA27DB77A909F5ECB35183CB26A969A6775936780936FE239E4F9C66B458'
$sdkInstalledNow = $false
$msiToolsInstalledNow = $false
$installerHash = $null
$payloadHashes = [ordered]@{
    'MsiVal2-x86_en-us.msi' = 'AF8FB98D0614670971A3D848CF048DE9910752FF21AE834B9D038C514BAC676B'
    '8e4755178e6b5bcba8d3538c3630b7a5.cab' = '296670D9FED15C149CFB5655CD9E86EE9D91A1662A243632F572311B68C5501A'
    'b80b7321357f7c9f281536f9440dfe68.cab' = 'F4417618F207A6AF7971F1266E86E175807B1BE07FB5DF727A56EAAC9678DBC7'
    'c2aabf6ea5c1d348ec22f3aeb92f8656.cab' = 'F6479BC17C44CCEB20DE4E752FE29260B10BE12DE0A09CA0E664C5F132C18D9D'
}

function Assert-ContainedFile([string]$Path, [string]$Root) {
    $full = [IO.Path]::GetFullPath($Path)
    $base = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    if (!$full.StartsWith($base + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "SDK tool path escapes approved root: $full"
    }
    $walk = (Get-Item -LiteralPath $full -Force).FullName
    while ($walk.Length -ge $base.Length) {
        $item = Get-Item -LiteralPath $walk -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "SDK tool path contains a reparse point: $walk"
        }
        if ($walk -ieq $base) { break }
        $walk = [IO.Path]::GetDirectoryName($walk)
    }
}

function Get-MicrosoftSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or !$signature.SignerCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(?i)(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Microsoft Authenticode verification failed: $Path ($($signature.Status))"
    }
    return $signature
}

function Find-SdkToolPair([bool]$AllowStandalone) {
    $roots = @($kitRoot)
    if ($AllowStandalone) { $roots += $standaloneRoot }
    foreach ($root in $roots) {
        if (!(Test-Path -LiteralPath $root -PathType Container)) { continue }
        $executables = @(Get-ChildItem -LiteralPath $root -Filter 'Msival2.exe' -File -Recurse -ErrorAction Stop |
            Sort-Object -Property FullName)
        foreach ($exe in $executables) {
            if ($root -ieq $kitRoot -and
                $exe.FullName -notmatch '(?i)\\bin\\10\.0\.26100\.0\\x86\\Msival2\.exe$') { continue }
            $cubPath = Join-Path $exe.DirectoryName 'darice.cub'
            if (!(Test-Path -LiteralPath $cubPath -PathType Leaf)) { continue }
            Assert-ContainedFile $exe.FullName $root
            Assert-ContainedFile $cubPath $root
            $cub = Get-Item -LiteralPath $cubPath -Force
            if ($exe.Length -lt 16KB -or $exe.Length -gt 32MB -or
                $cub.Length -lt 1KB -or $cub.Length -gt 16MB) {
                throw 'Windows SDK Msival2 or Darice size is outside bounded limits'
            }
            $signature = Get-MicrosoftSignature $exe.FullName
            return [pscustomobject]@{
                Tool = $exe.FullName
                Cub = $cub.FullName
                Root = $root
                Signature = $signature
            }
        }
    }
    return $null
}

function Find-PinnedMsiToolsPayload {
    $directory = Join-Path $kitRoot 'bin\10.0.26100.0\x86'
    $msi = Join-Path $directory 'MsiVal2-x86_en-us.msi'
    if (!(Test-Path -LiteralPath $msi -PathType Leaf)) { return $null }
    foreach ($fileName in $payloadHashes.Keys) {
        $path = Join-Path $directory $fileName
        if (!(Test-Path -LiteralPath $path -PathType Leaf)) { throw "SDK MSI Tools payload is incomplete: $fileName" }
        Assert-ContainedFile $path $kitRoot
        $file = Get-Item -LiteralPath $path -Force
        if ($file.Length -lt 1KB -or $file.Length -gt 32MB) { throw "SDK MSI Tools payload size is invalid: $fileName" }
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($hash -cne $payloadHashes[$fileName]) { throw "SDK MSI Tools payload hash differs from pinned signed 26100 package: $fileName" }
        [void](Get-MicrosoftSignature $path)
    }
    return $msi
}

function Download-PinnedSdk([string]$Destination) {
    $allowedHosts = @('download.microsoft.com')
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(120)
    $cancel = [Threading.CancellationTokenSource]::new()
    $cancel.CancelAfter(120000)
    $uri = [Uri]$sdkUrl
    try {
        for ($redirect = 0; $redirect -le 3; $redirect++) {
            if ($uri.Scheme -cne 'https' -or $uri.Host -notin $allowedHosts) {
                throw "Unexpected SDK download origin: $uri"
            }
            $response = $client.GetAsync($uri, [Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
                    if (!$response.Headers.Location -or $redirect -eq 3) { throw 'SDK redirect limit exceeded' }
                    $uri = [Uri]::new($uri, $response.Headers.Location)
                    continue
                }
                if (!$response.IsSuccessStatusCode) { throw "SDK HTTP status $([int]$response.StatusCode)" }
                $length = $response.Content.Headers.ContentLength
                if ($length -and ($length -lt 16KB -or $length -gt 32MB)) {
                    throw 'SDK installer Content-Length outside bounded limits'
                }
                $inputStream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
                $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {
                    $buffer = [byte[]]::new(65536)
                    $total = 0L
                    while (($read = $inputStream.ReadAsync($buffer, 0, $buffer.Length, $cancel.Token).GetAwaiter().GetResult()) -gt 0) {
                        $total += $read
                        if ($total -gt 32MB) { throw 'SDK installer exceeded size limit' }
                        $outputStream.Write($buffer, 0, $read)
                    }
                } finally {
                    $outputStream.Dispose()
                    $inputStream.Dispose()
                }
                if ($total -lt 16KB) { throw 'SDK installer is unexpectedly small' }
                return
            } finally { $response.Dispose() }
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
        $cancel.Dispose()
    }
    throw 'SDK installer was not downloaded'
}

$pair = Find-SdkToolPair $false
if (!$pair) {
    $payload = Find-PinnedMsiToolsPayload
    if (!$payload) {
    # Official SDK 10.0.26100.7705 installer and an observed Visual Studio SDK
    # setup feature identifier. Post-install discovery is mandatory.
    $installer = Join-Path $env:RUNNER_TEMP ('vpn013-winsdksetup-' + [guid]::NewGuid().ToString('N') + '.exe')
    try {
        Download-PinnedSdk $installer
        $installerHash = (Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($installerHash -cne $sdkSha256) { throw 'Windows SDK installer SHA-256 mismatch' }
        [void](Get-MicrosoftSignature $installer)
        $process = Start-Process -FilePath $installer -ArgumentList @('/features', 'OptionId.MSIInstallTools', '/quiet', '/norestart') -WindowStyle Hidden -PassThru
        if (!$process.WaitForExit(600000)) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            throw 'Windows SDK MSI Tools installer timed out'
        }
        if ($process.ExitCode -ne 0) {
            throw "Windows SDK MSI Tools installer failed or requested reboot: $($process.ExitCode)"
        }
        $sdkInstalledNow = $true
    } finally {
        Remove-Item -LiteralPath $installer -Force -ErrorAction SilentlyContinue
    }
    $payload = Find-PinnedMsiToolsPayload
    if (!$payload) { throw 'SDK MSI Tools feature completed without the pinned official MsiVal2 MSI and CAB payload' }
    }
    $msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    [void](Get-MicrosoftSignature $msiexec)
    $process = Start-Process -FilePath $msiexec -ArgumentList @('/i', ('"' + $payload + '"'), '/qn', '/norestart') -WindowStyle Hidden -PassThru
    if (!$process.WaitForExit(300000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        throw 'Windows SDK MsiVal2 package installation timed out'
    }
    if ($process.ExitCode -ne 0) { throw "Windows SDK MsiVal2 package installation failed or requested reboot: $($process.ExitCode)" }
    $msiToolsInstalledNow = $true
    $pair = Find-SdkToolPair $true
    if (!$pair) { throw 'Signed SDK MsiVal2 package installed without same-directory Msival2.exe and Darice.cub' }
}

$toolHash = (Get-FileHash -LiteralPath $pair.Tool -Algorithm SHA256).Hash.ToUpperInvariant()
$cubHash = (Get-FileHash -LiteralPath $pair.Cub -Algorithm SHA256).Hash.ToUpperInvariant()
$versionInfo = (Get-Item -LiteralPath $pair.Tool).VersionInfo
$evidence = [ordered]@{
    requestedSdkBootstrapVersion = $sdkVersion
    sdkBootstrapUrl = $(if ($sdkInstalledNow) { $sdkUrl } else { $null })
    sdkBootstrapSHA256 = $installerHash
    sdkInstalledNow = $sdkInstalledNow
    msiToolsPackageInstalledNow = $msiToolsInstalledNow
    pinnedMsiToolsPayloadSHA256 = $payloadHashes
    msival2Path = $pair.Tool
    msival2SHA256 = $toolHash
    msival2FileVersion = $versionInfo.FileVersion
    msival2Signer = $pair.Signature.SignerCertificate.Subject
    msival2SignerThumbprint = $pair.Signature.SignerCertificate.Thumbprint
    daricePath = $pair.Cub
    dariceSHA256 = $cubHash
    dariceBytes = (Get-Item -LiteralPath $pair.Cub).Length
    trustedSdkRoot = $pair.Root
}
$evidencePath = Join-Path $env:RUNNER_TEMP 'vpn013-msi-validator-provenance.json'
$evidence | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $evidencePath -Encoding utf8
Add-Content -LiteralPath $env:GITHUB_ENV -Value "MSIVAL2_PATH=$($pair.Tool)" -Encoding utf8
Add-Content -LiteralPath $env:GITHUB_ENV -Value "DARICE_CUB_PATH=$($pair.Cub)" -Encoding utf8
Write-Output "PASS: Microsoft-signed Msival2.exe and same-directory Darice.cub from $($pair.Root); SHA256 $toolHash / $cubHash; evidence $evidencePath"
