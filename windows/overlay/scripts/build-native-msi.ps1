param(
    [Parameter(Mandatory)][string]$TemplateMsi,
    [Parameter(Mandatory)][string]$SourceRoot,
    [Parameter(Mandatory)][string]$PayloadRoot,
    [Parameter(Mandatory)][string]$OutputMsi,
    [Parameter(Mandatory)][string]$ExpectedSourceManifestSha256,
    [Parameter(Mandatory)][string]$ExpectedInstallerWxsSha256,
    [Parameter(Mandatory)][string]$ExpectedCustomActionsSourceSha256,
    [Parameter(Mandatory)][string]$GitCommit
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows' -or $env:GITHUB_REPOSITORY -ne '2njz45z86r-commits/vpn013-wg-ios' -or $GitCommit -ne $env:GITHUB_SHA) {
    throw 'Release MSI assembly requires the authorized GitHub-hosted Windows runner and its exact commit'
}

function Assert([bool]$condition,[string]$message) { if (!$condition) {throw $message} }
function Hash([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Assert-X64PE([string]$path,[bool]$expectDll) {
    $fs=[IO.File]::OpenRead($path);$br=[IO.BinaryReader]::new($fs)
    try {
        Assert ($br.ReadUInt16() -eq 0x5a4d) "Not a PE file: $path"
        $fs.Position=0x3c;$pe=[int]$br.ReadUInt32()
        Assert ($pe -ge 0x40 -and $pe -lt $fs.Length-26) "Invalid PE offset: $path"
        $fs.Position=$pe
        Assert ($br.ReadUInt32() -eq 0x00004550 -and $br.ReadUInt16() -eq 0x8664) "Not amd64 PE: $path"
        $fs.Position=$pe+22;$characteristics=$br.ReadUInt16()
        if($expectDll){Assert (($characteristics -band 0x2000) -ne 0) "Custom actions is not a DLL: $path"}
        $fs.Position=$pe+24
        Assert ($br.ReadUInt16() -eq 0x20b) "Not PE32+ x64: $path"
    } finally {$br.Dispose();$fs.Dispose()}
}
function QueryRows($db,[string]$sql) {
    $view=$db.OpenView($sql)
    try {
        $null=$view.Execute()
        $rows=@()
        while ($r=$view.Fetch()) {$rows+=,$r}
        return ,$rows
    } finally {
        $null=$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}
function Update-Row($db,[string]$sql,[scriptblock]$change,[int]$mode=2) {
    Assert ($mode -eq 2 -or $mode -eq 4) 'Unsupported MSI row modification mode'
    $view=$db.OpenView($sql)
    $r=$null
    try {
        $null=$view.Execute()
        $r=$view.Fetch()
        Assert ($null -ne $r) "Missing row: $sql"
        & $change $r
        try {$null=$view.Modify($mode,$r)} catch {
            # Capture immediately: a subsequent MSI operation can reset LastErrorRecord.
            # Only expose the numeric MSI error, never record parameters or file paths.
            $detail='unavailable'
            try {
                $errorRecord=$installer.LastErrorRecord()
                if ($null -ne $errorRecord) {
                    $formatted=$errorRecord.FormatText()
                    if ($formatted -match '^1:\s*(\d+)') {$detail=$Matches[1]}
                    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($errorRecord)
                }
            } catch {}
            $table=if($sql -match 'FROM\s+`([A-Za-z_][A-Za-z_0-9]*)`'){$Matches[1]}else{'unknown'}
            throw "MSI Modify failed: table=$table mode=$mode error=$detail"
        }
    } finally {
        $null=$view.Close()
        if ($null -ne $r) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($r)}
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}
function Cab-Names([string]$path) {
    # CFHEADER and CFFILE entries; this package uses one non-spanning cabinet.
    $fs=[IO.File]::OpenRead($path)
    $br=[IO.BinaryReader]::new($fs)
    try {
        Assert ($br.ReadUInt32() -eq 0x4643534d) 'CAB signature mismatch'
        $null=$br.ReadUInt32(); $cabSize=$br.ReadUInt32(); $null=$br.ReadUInt32()
        $fileOffset=$br.ReadUInt32(); $null=$br.ReadUInt32()
        $minor=$br.ReadByte(); $major=$br.ReadByte(); $folders=$br.ReadUInt16(); $files=$br.ReadUInt16(); $flags=$br.ReadUInt16()
        Assert ($cabSize -eq $fs.Length -and $major -eq 1 -and $folders -eq 1 -and $files -eq 4 -and $flags -eq 0) 'Unexpected CAB layout'
        $fs.Position=$fileOffset
        $names=@()
        for($n=0;$n -lt $files;$n++) {
            $null=$br.ReadUInt32(); $null=$br.ReadUInt32(); $folderIndex=$br.ReadUInt16()
            $null=$br.ReadUInt16(); $null=$br.ReadUInt16(); $null=$br.ReadUInt16()
            Assert ($folderIndex -eq 0) 'CAB spans another folder'
            $bytes=[Collections.Generic.List[byte]]::new()
            while(($b=$br.ReadByte()) -ne 0) {$bytes.Add($b); Assert ($bytes.Count -le 72) 'CAB name too long'}
            $names+=,[Text.Encoding]::ASCII.GetString($bytes.ToArray())
        }
        return ,$names
    } finally {$br.Dispose();$fs.Dispose()}
}

$template=(Resolve-Path -LiteralPath $TemplateMsi).Path
$source=(Resolve-Path -LiteralPath $SourceRoot).Path
$payload=(Resolve-Path -LiteralPath $PayloadRoot).Path
$TargetVersion='1.5.7'
$output=[IO.Path]::GetFullPath($OutputMsi)
$workParent=if($env:RUNNER_TEMP){[IO.Path]::GetFullPath($env:RUNNER_TEMP)}else{[IO.Path]::GetDirectoryName($output)}
$work=[IO.Path]::Combine($workParent,'native-msi-'+[guid]::NewGuid().ToString('N'))
Assert ($work -cmatch '^[\x20-\x7E]+$' -and $work -notmatch '["`\r\n]') 'makecab staging path must be plain ASCII'
Assert ((Hash $template) -eq '4b3e1e94ad2c2df1fd441a5857693a6b1eefb4cd5cc808e8da606b1eb3d1d68c') 'Template MSI SHA-256 differs from pinned public 1.5.6'
Assert ($GitCommit -match '^[0-9a-fA-F]{40}$') 'Exact GITHUB_SHA is required'
Assert ($payload -eq $source) 'Release payload must come from the prepared source root'
Assert ($output -ne $template -and !(Test-Path -LiteralPath $output)) 'Output must be new and distinct from template'
Assert (!(Test-Path -LiteralPath $work)) 'Private work directory already exists'
$versionText=Get-Content -LiteralPath (Join-Path $source 'version/version.go') -Raw
Assert ($versionText -match 'Number\s*=\s*"1\.5\.7"') 'Release source/version mismatch'
Assert ((Test-Path -LiteralPath (Join-Path $source 'installer/wireguard.wxs')) -and (Test-Path -LiteralPath (Join-Path $source 'installer/customactions.c'))) 'Installer source missing'
foreach($pin in @($ExpectedSourceManifestSha256,$ExpectedInstallerWxsSha256,$ExpectedCustomActionsSourceSha256)) {Assert ($pin -match '^[0-9a-fA-F]{64}$') 'Release source SHA-256 pins are required'}
Assert ((Hash (Join-Path $source 'SOURCE-MANIFEST.json')) -eq $ExpectedSourceManifestSha256.ToLowerInvariant()) 'Source manifest pin mismatch'
Assert ((Hash (Join-Path $source 'installer/wireguard.wxs')) -eq $ExpectedInstallerWxsSha256.ToLowerInvariant()) 'Installer layout source pin mismatch'
Assert ((Hash (Join-Path $source 'installer/customactions.c')) -eq $ExpectedCustomActionsSourceSha256.ToLowerInvariant()) 'Custom actions source pin mismatch'
Assert ($ExpectedInstallerWxsSha256 -eq '4f2291a8aeda1cafefca419c620663bfc0d15ebf161c754d4fef7f63776f6191') 'Prepared MSI layout differs from the reviewed 1.5.7 source'
Assert ($ExpectedCustomActionsSourceSha256 -eq '0d3b37a4f2a7308da0433c8483c55bf0fb8cedc228d1927c4bcdc6a3d8527ea2') 'Custom actions source differs from the reviewed 1.5.7 source'
$sourceManifest=Get-Content -LiteralPath (Join-Path $source 'SOURCE-MANIFEST.json') -Raw | ConvertFrom-Json
foreach($entry in @(@('installer/wireguard.wxs',$ExpectedInstallerWxsSha256),@('installer/customactions.c',$ExpectedCustomActionsSourceSha256),@('version/version.go',(Hash (Join-Path $source 'version/version.go'))))) {
    $listed=@($sourceManifest | Where-Object {$_.path -eq ('vpn013-wg-windows/'+$entry[0])})
    Assert ($listed.Count -eq 1 -and $listed[0].sha256 -eq $entry[1]) "Source manifest entry mismatch: $($entry[0])"
}

$files=[ordered]@{
    'awg.exe'='awg.exe'
    'THIRD_PARTY_NOTICES.txt'='THIRD_PARTY_NOTICES.txt'
    'VPN013WG.exe'='VPN013WG.exe'
    'wintun.dll'='wintun.dll'
}
$payloadPaths=[ordered]@{}
foreach($id in $files.Keys) {
    if($id -eq 'THIRD_PARTY_NOTICES.txt') {$path=Join-Path $payload 'THIRD-PARTY-NOTICES.txt'}
    else {$path=Join-Path (Join-Path $payload 'amd64') $files[$id]}
    Assert (Test-Path -LiteralPath $path -PathType Leaf) "Payload missing: $id"
    $payloadPaths[$id]=(Resolve-Path -LiteralPath $path).Path
}
$caPath=Join-Path $payload 'installer/amd64/customactions.dll'
Assert (Test-Path -LiteralPath $caPath -PathType Leaf) 'Built customactions.dll missing'
$caPath=(Resolve-Path -LiteralPath $caPath).Path
$installer=New-Object -ComObject WindowsInstaller.Installer
$exeVersion=$installer.FileVersion($payloadPaths['VPN013WG.exe'],$false)
Assert ($exeVersion -eq "$TargetVersion.0") 'Main executable file version does not match package target'
Assert ((Get-AuthenticodeSignature -LiteralPath $payloadPaths['wintun.dll']).Status -eq 'Valid') 'Wintun signature invalid'
Assert ((Hash $payloadPaths['wintun.dll']) -eq 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce') 'Wintun differs from pinned source'
foreach($path in @($payloadPaths['awg.exe'],$payloadPaths['VPN013WG.exe'],$payloadPaths['wintun.dll'])) {Assert-X64PE $path $false}
Assert-X64PE $caPath $true

New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null
$staged=Join-Path $work 'payload';New-Item -ItemType Directory -Path $staged -ErrorAction Stop | Out-Null
foreach($id in $files.Keys) {
    $destination=Join-Path $staged $id
    [IO.File]::Copy($payloadPaths[$id],$destination,$false)
    Assert ((Hash $destination) -eq (Hash $payloadPaths[$id])) "Staged file hash changed: $id"
}
$stagedCA=Join-Path $staged 'customactions.dll'
[IO.File]::Copy($caPath,$stagedCA,$false)
Assert ((Hash $stagedCA) -eq (Hash $caPath)) 'Staged custom actions hash changed'
$cabPath=Join-Path $work 'cab1.cab'
$ddf=Join-Path $work 'cab1.ddf'
$ddfLines=@('.OPTION EXPLICIT','.Set Cabinet=on','.Set Compress=on','.Set CompressionType=MSZIP','.Set CabinetNameTemplate=cab1.cab',(".Set DiskDirectoryTemplate=$work"),'.Set MaxDiskSize=0')
foreach($id in $files.Keys) {$ddfLines+='"'+(Join-Path $staged $id)+'" "'+$id+'"'}
[IO.File]::WriteAllLines($ddf,$ddfLines,[Text.Encoding]::ASCII)
Push-Location $work
try {
    & "$env:SystemRoot\System32\makecab.exe" /f $ddf *> (Join-Path $work 'makecab.log')
    Assert ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $cabPath)) 'makecab failed'
} finally {Pop-Location}
Assert ((@((Cab-Names $cabPath)) -join '|') -eq (@($files.Keys) -join '|')) 'CAB internal names/order differ from File.Sequence'

[IO.File]::Copy($template,$output,$false)
$db=$installer.OpenDatabase($output,1)
$newProduct='{'+([guid]::NewGuid().ToString().ToUpperInvariant())+'}'
$newPackage='{'+([guid]::NewGuid().ToString().ToUpperInvariant())+'}'
try {
    $oldProductRows=QueryRows $db 'SELECT `Property`,`Value` FROM `Property` WHERE `Property`=''ProductCode'''
    $oldUpgradeRows=QueryRows $db 'SELECT `Property`,`Value` FROM `Property` WHERE `Property`=''UpgradeCode'''
    $oldProduct=$oldProductRows[0].StringData(2)
    $oldUpgrade=$oldUpgradeRows[0].StringData(2)
    foreach($record in @($oldProductRows)+@($oldUpgradeRows)) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)}
    Assert ($oldProduct -eq '{E69BC1A6-7758-4FDC-AC2A-7E9952B49CC0}' -and $oldUpgrade -eq '{7669E7D6-2D96-51EF-B972-DCE59D214438}') 'Unexpected template identity'
    Update-Row $db 'SELECT `Property`,`Value` FROM `Property` WHERE `Property`=''ProductCode''' {param($r)$r.StringData(2)=$newProduct}
    Update-Row $db 'SELECT `Property`,`Value` FROM `Property` WHERE `Property`=''ProductVersion''' {param($r)$r.StringData(2)=$TargetVersion}
    $upgradeRows=QueryRows $db 'SELECT * FROM `Upgrade`'
    Assert ($upgradeRows.Count -eq 2) 'Unexpected Upgrade row count'
    foreach($record in $upgradeRows) {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)}
    # VersionMin and VersionMax are Upgrade primary keys; Replace (4) handles key changes.
    Update-Row $db 'SELECT * FROM `Upgrade` WHERE `ActionProperty`=''WIX_UPGRADE_DETECTED''' {param($r) Assert ($r.StringData(3) -eq '1.5.6') 'Unexpected original upgrade ceiling'; $r.StringData(3)=$TargetVersion} 4
    Update-Row $db 'SELECT * FROM `Upgrade` WHERE `ActionProperty`=''WIX_DOWNGRADE_DETECTED''' {param($r) Assert ($r.StringData(2) -eq '1.5.6') 'Unexpected original downgrade floor'; $r.StringData(2)=$TargetVersion} 4
    foreach($id in $files.Keys) {
        $path=$payloadPaths[$id]
        $size=(Get-Item -LiteralPath $path).Length
        Assert ($size -gt 0 -and $size -lt [int]::MaxValue) "Bad file size: $id"
        $version=$installer.FileVersion($path,$false)
        $language=$installer.FileVersion($path,$true)
        Update-Row $db ("SELECT * FROM ``File`` WHERE ``File``='$id'") {
            param($r)
            $r.IntegerData(4)=[int]$size
            $r.StringData(5)=[string]$version
            $r.StringData(6)=[string]$language
        }
        if (!$version) {
            Assert ($id -eq 'THIRD_PARTY_NOTICES.txt') "Unexpected unversioned payload: $id"
            $h=$installer.FileHash($path,0)
            Update-Row $db ("SELECT * FROM ``MsiFileHash`` WHERE ``File_``='$id'") {
                param($r)
                for($n=1;$n -le 4;$n++) {$r.IntegerData($n+2)=$h.IntegerData($n)}
            }
        }
    }
    Update-Row $db 'SELECT `Name`,`Data` FROM `_Streams` WHERE `Name`=''cab1.cab''' {param($r)$r.SetStream(2,$cabPath)}
    Update-Row $db 'SELECT `Name`,`Data` FROM `Binary` WHERE `Name`=''customactions.dll''' {param($r)$r.SetStream(2,$stagedCA)}
    $summary=$db.SummaryInformation(1)
    $summary.Property(9)=$newPackage
    $summary.Persist()
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)
    $db.Commit()
} finally {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($db)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
}
[GC]::Collect(); [GC]::WaitForPendingFinalizers()

[ordered]@{
    templateSHA256=Hash $template
    sourceManifestSHA256=Hash (Join-Path $source 'SOURCE-MANIFEST.json')
    installerWxsSHA256=Hash (Join-Path $source 'installer/wireguard.wxs')
    customActionsSourceSHA256=Hash (Join-Path $source 'installer/customactions.c')
    targetVersion=$TargetVersion
    sourceCommit=$GitCommit.ToLowerInvariant()
    oldProductCode=$oldProduct
    productCode=$newProduct
    packageCode=$newPackage
    payloadSHA256=[ordered]@{awg=Hash $payloadPaths['awg.exe'];notices=Hash $payloadPaths['THIRD_PARTY_NOTICES.txt'];main=Hash $payloadPaths['VPN013WG.exe'];wintun=Hash $payloadPaths['wintun.dll'];customActions=Hash $caPath}
    cabSHA256=Hash $cabPath
    outputSHA256=Hash $output
} | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$output.provenance.json" -Encoding utf8
$null=& (Join-Path $PSScriptRoot 'verify-native-msi.ps1') -TemplateMsi $template -CandidateMsi $output -PayloadRoot $staged
Write-Output "Built private MSI database copy: $output"
