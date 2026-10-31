param(
    [Parameter(Mandatory)][string]$TemplateMsi,
    [Parameter(Mandatory)][string]$CandidateMsi,
    [Parameter(Mandatory)][string]$PayloadRoot
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Assert([bool]$ok,[string]$why) {if(!$ok){throw $why}}
function Hash([string]$path) {(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Rows([string]$msi) {
    $i=New-Object -ComObject WindowsInstaller.Installer
    $d=$i.OpenDatabase($msi,0)
    try {
        $tables=@('_Tables')
        $catalog=$d.OpenView('SELECT `Name` FROM `_Tables`')
        try {
            $null=$catalog.Execute()
            while($entry=$catalog.Fetch()) {
                $tables+=,$entry.StringData(1)
                [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($entry)
            }
        } finally {$null=$catalog.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($catalog)}
        $results=@()
        foreach($table in $tables) {
            Assert ($table -match '^[A-Za-z_][A-Za-z_0-9]*$') "Unexpected table name: $table"
            $v=$d.OpenView("SELECT * FROM ``$table``")
            try {
                $null=$v.Execute()
                while($r=$v.Fetch()) {
                    $fieldCount=$r.GetType().InvokeMember('FieldCount','GetProperty',$null,$r,$null)
                    $values=@(for($n=1;$n -le $fieldCount;$n++){try{$r.StringData($n)}catch{'<binary>'}})
                    $results+=,[pscustomobject]@{Table=$table;Values=$values}
                    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($r)
                }
            } finally {$null=$v.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($v)}
        }
        $v=$d.OpenView('SELECT `Name` FROM `_Streams`')
        try {
            $null=$v.Execute()
            while($r=$v.Fetch()){$results+=,[pscustomobject]@{Table='_Streams';Values=@($r.StringData(1))};[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($r)}
        } finally {$null=$v.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($v)}
        $summary=$d.SummaryInformation(0)
        foreach($n in @(1,2,3,4,5,6,7,8,9,14,15,18)) {
            try{$results+=,[pscustomobject]@{Table='_Summary';Values=@($n,[string]$summary.Property($n))}}catch{}
        }
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($summary)
        return ,$results
    } finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($d)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($i)
    }
}
function Extract-Stream([string]$msi,[string]$name,[string]$destination) {
    $i=New-Object -ComObject WindowsInstaller.Installer
    $d=$i.OpenDatabase($msi,0)
    try {
        $v=$d.OpenView('SELECT `Data` FROM `_Streams` WHERE `Name`=?')
        $q=$i.CreateRecord(1);$q.StringData(1)=$name
        $null=$v.Execute($q)
        try {
            $r=$v.Fetch();Assert ($null -ne $r) "Missing MSI stream: $name"
            $fs=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {
                while($true) {
                    $s=$r.ReadStream(1,65536,1)
                    if([string]::IsNullOrEmpty($s)){break}
                    $bytes=[byte[]]::new($s.Length)
                    for($n=0;$n -lt $s.Length;$n++){$bytes[$n]=[byte][char]$s[$n]}
                    $fs.Write($bytes,0,$bytes.Length)
                }
            } finally {$fs.Dispose()}
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($r)
        } finally {$null=$v.Close();[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($q);[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($v)}
    } finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($d)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($i)
    }
}
function TableRows($all,[string]$table) {@($all | Where-Object {$_.Table -eq $table})}
function MapByFirst($rows) {
    $m=@{}
    foreach($r in $rows) {Assert (!$m.ContainsKey([string]$r.Values[0])) 'Duplicate MSI row key'; $m[[string]$r.Values[0]]=$r.Values}
    return ,$m
}
function Same($a,$b,[string]$reason) {Assert ((ConvertTo-Json -InputObject $a -Depth 8 -Compress) -ceq (ConvertTo-Json -InputObject $b -Depth 8 -Compress)) $reason}

$template=(Resolve-Path -LiteralPath $TemplateMsi).Path
$candidate=(Resolve-Path -LiteralPath $CandidateMsi).Path
$payload=(Resolve-Path -LiteralPath $PayloadRoot).Path
$manifest=Get-Content -LiteralPath "$candidate.provenance.json" -Raw | ConvertFrom-Json
Assert ((Hash $template) -eq '4b3e1e94ad2c2df1fd441a5857693a6b1eefb4cd5cc808e8da606b1eb3d1d68c') 'Template hash wrong'
Assert ((Hash $candidate) -eq $manifest.outputSHA256) 'Candidate hash differs from provenance'
$old=Rows $template
$new=Rows $candidate
$oldTables=TableRows $old '_Tables'
$newTables=TableRows $new '_Tables'
Same @($oldTables | ForEach-Object {$_.Values[0]} | Sort-Object) @($newTables | ForEach-Object {$_.Values[0]} | Sort-Object) 'MSI table set changed'
$allowed=@('Property','File','Upgrade','MsiFileHash','_Summary')
foreach($table in @($oldTables | ForEach-Object {$_.Values[0]} | Where-Object {$_ -notin $allowed}) + @('_Tables','_Streams')) {
    $a=@(TableRows $old $table | ForEach-Object {$_.Values -join '|'} | Sort-Object)
    $b=@(TableRows $new $table | ForEach-Object {$_.Values -join '|'} | Sort-Object)
    Same $a $b "Unexpected table change: $table"
}
$pOld=MapByFirst (TableRows $old 'Property')
$pNew=MapByFirst (TableRows $new 'Property')
Same @($pOld.Keys|Sort-Object) @($pNew.Keys|Sort-Object) 'Property keys changed'
foreach($key in $pOld.Keys) {
    if($key -eq 'ProductCode') {
        Assert ($pNew[$key][1] -eq $manifest.productCode -and $pNew[$key][1] -ne $pOld[$key][1]) 'ProductCode incorrect'
    } elseif($key -eq 'ProductVersion') {
        Assert ($pOld[$key][1] -eq '1.5.6' -and $pNew[$key][1] -eq $manifest.targetVersion) 'ProductVersion incorrect'
    } else {Same $pOld[$key] $pNew[$key] "Property changed: $key"}
}
Assert ($pNew['UpgradeCode'][1] -eq '{7669E7D6-2D96-51EF-B972-DCE59D214438}') 'UpgradeCode changed'
$fOld=MapByFirst (TableRows $old 'File')
$fNew=MapByFirst (TableRows $new 'File')
Same @($fOld.Keys|Sort-Object) @($fNew.Keys|Sort-Object) 'File keys changed'
$installer=New-Object -ComObject WindowsInstaller.Installer
try {
    foreach($id in $fOld.Keys) {
        $a=@($fOld[$id]);$b=@($fNew[$id])
        $a[3]=$b[3];$a[4]=$b[4];$a[5]=$b[5]
        Same $a $b "File component/name/flags/sequence changed: $id"
        $path=Join-Path $payload $id
        Assert (Test-Path -LiteralPath $path -PathType Leaf) "Missing payload: $id"
        Assert ([int64]$b[3] -eq (Get-Item -LiteralPath $path).Length) "File size mismatch: $id"
        Assert ([string]$b[4] -eq [string]$installer.FileVersion($path,$false) -and [string]$b[5] -eq [string]$installer.FileVersion($path,$true)) "File version/language mismatch: $id"
    }
    $hashOld=MapByFirst (TableRows $old 'MsiFileHash')
    $hashNew=MapByFirst (TableRows $new 'MsiFileHash')
    Same @($hashOld.Keys|Sort-Object) @($hashNew.Keys|Sort-Object) 'MsiFileHash keys changed'
    Assert ($hashNew.Count -eq 1 -and $hashNew.ContainsKey('THIRD_PARTY_NOTICES.txt')) 'Unexpected unversioned hash rows'
    $h=$installer.FileHash((Join-Path $payload 'THIRD_PARTY_NOTICES.txt'),0)
    for($n=1;$n -le 4;$n++) {Assert ([int]$hashNew['THIRD_PARTY_NOTICES.txt'][$n+1] -eq $h.IntegerData($n)) 'Notices MSI file hash mismatch'}
} finally {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)}
$uOld=MapByFirst (TableRows $old 'Upgrade' | ForEach-Object {[pscustomobject]@{Values=@($_.Values[6])+@($_.Values)}})
$uNew=MapByFirst (TableRows $new 'Upgrade' | ForEach-Object {[pscustomobject]@{Values=@($_.Values[6])+@($_.Values)}})
Same @($uOld.Keys|Sort-Object) @($uNew.Keys|Sort-Object) 'Upgrade action properties changed'
foreach($key in $uOld.Keys) {
    $a=@($uOld[$key]);$b=@($uNew[$key]);$idx=if($key -eq 'WIX_UPGRADE_DETECTED'){3}elseif($key -eq 'WIX_DOWNGRADE_DETECTED'){2}else{throw "Unexpected Upgrade action: $key"}
    Assert ($a[$idx] -eq '1.5.6' -and $b[$idx] -eq $manifest.targetVersion) "Upgrade version wrong: $key"
    $a[$idx]=$b[$idx];Same $a $b "Other Upgrade fields changed: $key"
}
$sOld=MapByFirst (TableRows $old '_Summary')
$sNew=MapByFirst (TableRows $new '_Summary')
Same @($sOld.Keys|Sort-Object) @($sNew.Keys|Sort-Object) 'Summary property set changed'
foreach($key in $sOld.Keys) {
    if($key -eq '9') {Assert ($sNew[$key][1] -eq $manifest.packageCode -and $sNew[$key][1] -ne $sOld[$key][1]) 'PackageCode invalid'}
    else {Same $sOld[$key] $sNew[$key] "Summary property changed: $key"}
}

$scratchParent=if($env:GITHUB_ACTIONS -eq 'true' -and $env:RUNNER_TEMP){$env:RUNNER_TEMP}else{Split-Path $candidate}
$scratch=Join-Path $scratchParent ([IO.Path]::GetFileNameWithoutExtension($candidate)+'-verify-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch -ErrorAction Stop | Out-Null
$cab=Join-Path $scratch 'cab1.cab';$ca=Join-Path $scratch 'customactions.dll'
Extract-Stream $candidate 'cab1.cab' $cab
Extract-Stream $candidate 'Binary.customactions.dll' $ca
$oldIcon=Join-Path $scratch 'template-icon.ico';$newIcon=Join-Path $scratch 'candidate-icon.ico'
Extract-Stream $template 'Icon.wireguard.ico' $oldIcon
Extract-Stream $candidate 'Icon.wireguard.ico' $newIcon
Assert ((Hash $oldIcon) -eq (Hash $newIcon)) 'Installer icon stream changed'
Assert ((Hash $cab) -eq $manifest.cabSHA256) 'Embedded CAB differs from source CAB'
Assert ((Hash $ca) -eq $manifest.payloadSHA256.customActions -and (Hash $ca) -eq (Hash (Join-Path $payload 'customactions.dll'))) 'Embedded custom actions DLL differs'
$expanded=Join-Path $scratch 'expanded';New-Item -ItemType Directory -Path $expanded | Out-Null
& "$env:SystemRoot\System32\expand.exe" -f:* $cab $expanded *> (Join-Path $scratch 'expand.log')
Assert ($LASTEXITCODE -eq 0) 'Embedded CAB expansion failed'
foreach($id in $fOld.Keys) {Assert ((Hash (Join-Path $expanded $id)) -eq (Hash (Join-Path $payload $id))) "Embedded payload differs: $id"}
[ordered]@{staticTablesPreserved=$true;productAndPackageCodesUnique=$true;upgradeVersion=$manifest.targetVersion;cabStreamVerified=$true;customActionsStreamVerified=$true;allPayloadBytesVerified=$true;installed=$false;upgradeTested=$false;msiSHA256=Hash $candidate} | ConvertTo-Json | Set-Content -LiteralPath "$candidate.static-verification.json" -Encoding utf8
Write-Output 'PASS: static MSI tables, IDs, streams, CAB extraction, and payload bytes; installation unverified'
