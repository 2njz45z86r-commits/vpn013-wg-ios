$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$projectRoot=Split-Path $PSScriptRoot -Parent
$cache=Join-Path $projectRoot '.deps/native-installer'
$template=Join-Path $cache 'VPN013WG-1.5.6-amd64.msi'
$expected='4b3e1e94ad2c2df1fd441a5857693a6b1eefb4cd5cc808e8da606b1eb3d1d68c'
$url=[Uri]'https://github.com/2njz45z86r-commits/vpn013-wg-ios/releases/download/windows-1.5.6/VPN013WG-1.5.6-amd64.msi'
$allowedHosts=@('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com')
$maxBytes=64MB

if(Test-Path -LiteralPath $template) {
    if((Get-FileHash -LiteralPath $template -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {throw 'Pinned 1.5.6 MSI cache mismatch'}
    Write-Output 'Pinned public 1.5.6 MSI template verified in local build cache'
    return
}
New-Item -ItemType Directory -Path $cache -Force | Out-Null
$temp=Join-Path $cache ('template-download-'+[guid]::NewGuid().ToString('N')+'.msi')
$handler=[Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect=$false
$handler.UseDefaultCredentials=$false
$handler.UseCookies=$false
$client=[Net.Http.HttpClient]::new($handler)
$client.Timeout=[TimeSpan]::FromMinutes(4)
$client.DefaultRequestHeaders.UserAgent.ParseAdd('VPN013-Windows-MSI-Bootstrap/1.0')
try {
    for($hop=0;$hop -le 5;$hop++) {
        if($url.Scheme -ne 'https' -or $url.Port -ne 443 -or $url.UserInfo -or $url.Host -notin $allowedHosts) {throw 'Installer template redirect host or scheme not allowed'}
        $request=[Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get,$url)
        try {$response=$client.SendAsync($request,[Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()}
        finally {$request.Dispose()}
        try {
            $status=[int]$response.StatusCode
            if($status -in @(301,302,303,307,308)) {
                if($hop -eq 5 -or $null -eq $response.Headers.Location) {throw 'Installer template redirect limit exceeded'}
                $url=[Uri]::new($url,$response.Headers.Location)
                continue
            }
            if($status -ne 200) {throw "Installer template HTTP status $status"}
            if($response.Content.Headers.ContentLength -gt $maxBytes) {throw 'Installer template exceeds size limit'}
            $inputStream=$response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $outputStream=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try {
                $buffer=[byte[]]::new(65536);$total=[int64]0
                while(($count=$inputStream.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $total+=$count
                    if($total -gt $maxBytes) {throw 'Installer template exceeds size limit'}
                    $outputStream.Write($buffer,0,$count)
                }
            } finally {$outputStream.Dispose();$inputStream.Dispose()}
            if((Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {throw 'Downloaded 1.5.6 MSI SHA-256 mismatch'}
            [IO.File]::Move($temp,$template)
            Write-Output 'Pinned public 1.5.6 MSI template downloaded and verified'
            return
        } finally {$response.Dispose()}
    }
    throw 'Installer template redirect limit exceeded'
} finally {
    $client.Dispose();$handler.Dispose()
    if(Test-Path -LiteralPath $temp) {[IO.File]::Delete($temp)}
}
