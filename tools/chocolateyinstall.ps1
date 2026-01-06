$pkgDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$isoPath = Join-Path $pkgDir virtio.iso

function Assert-CommandExists {
        param(
                [Parameter(Mandatory = $true)][string]$Name
        )

        if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
                throw "Required command '$Name' was not found on PATH."
        }
}

function Invoke-ExternalExe {
        param(
                [Parameter(Mandatory = $true)][string]$FilePath,
                [Parameter(Mandatory = $true)][string[]]$ArgumentList,
                [Parameter(Mandatory = $true)][string]$DisplayName
        )

        $tmp = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $stdoutFile = Join-Path $tmp 'stdout.txt'
        $stderrFile = Join-Path $tmp 'stderr.txt'

        try {
                $proc = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
                $stdout = @()
                $stderr = @()
                if (Test-Path $stdoutFile) { $stdout = Get-Content -LiteralPath $stdoutFile -ErrorAction SilentlyContinue }
                if (Test-Path $stderrFile) { $stderr = Get-Content -LiteralPath $stderrFile -ErrorAction SilentlyContinue }

                return [pscustomobject]@{
                        ExitCode = $proc.ExitCode
                        StdOut = $stdout
                        StdErr = $stderr
                        AllOutput = @($stdout + $stderr)
                        DisplayName = $DisplayName
                }
        }
        finally {
                Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        }
}

function Get-PnpPublishedName {
        param(
                [Parameter()][AllowEmptyCollection()][AllowNull()][string[]]$OutputLines = @()
        )

        if (-not $OutputLines -or $OutputLines.Count -eq 0) {
                return $null
        }

        foreach ($line in $OutputLines) {
                if ($line -match '(?i)^\s*Published\s+Name\s*:\s*(.+?)\s*$') {
                        return $Matches[1]
                }
        }

        foreach ($line in $OutputLines) {
                # Another common pattern within pnputil output is an OEM INF name somewhere in the text.
                if ($line -match '(?i)\b(oem\d+\.inf)\b') {
                        return $Matches[1]
                }
        }

        return $null
}

function Install-CatalogCertificateChain {
        param(
                [Parameter(Mandatory = $true)][string]$CatalogPath
        )

        if (-not (Test-Path -LiteralPath $CatalogPath)) {
                throw "Catalog file was not found: '$CatalogPath'"
        }

                $sig = Get-AuthenticodeSignature -LiteralPath $CatalogPath
                $signer = $sig.SignerCertificate
        if (-not $signer) {
            throw "Failed to extract signer certificate from catalog: '$CatalogPath'"
        }

                # Many environments can successfully install drivers by trusting the publisher certificate directly.
                # Do this up-front so we don't depend on a complete chain build (AIA fetch, Windows Update roots, etc.).
                Add-CertificateToStore -Certificate $signer -StoreName 'TrustedPublisher'
                Add-CertificateToStore -Certificate $signer -StoreName 'TrustedPeople'

        $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

        $null = $chain.Build($signer)
        if (-not $chain.ChainElements -or $chain.ChainElements.Count -eq 0) {
                throw "Could not build certificate chain from signer certificate for '$CatalogPath'."
        }

        $tmp = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null

        try {
                # Best-effort: install chain elements (root/intermediates).
                # Root (self-signed) -> Root store; intermediates -> CA store.
                $elements = @($chain.ChainElements | ForEach-Object { $_.Certificate })
                for ($i = 0; $i -lt $elements.Count; $i++) {
                        $c = $elements[$i]

                        $isSelfSigned = ($c.Subject -eq $c.Issuer)
                        $isSigner = ($c.Thumbprint -eq $signer.Thumbprint)
                        if ($isSigner) {
                                continue
                        }

                        $storeName = if ($isSelfSigned) { 'Root' } else { 'CA' }

                        $cerPath = Join-Path $tmp ("chain-{0:D2}-{1}.cer" -f $i, $storeName)
                        [IO.File]::WriteAllBytes($cerPath, $c.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))

                        $addResult = Invoke-ExternalExe -FilePath 'certutil.exe' -ArgumentList @('/addstore', '-f', $storeName, $cerPath) -DisplayName "certutil addstore $storeName"
                        $addResult.AllOutput | ForEach-Object { Write-Host $_ }
                        if ($addResult.ExitCode -ne 0) {
                                $details = ($addResult.AllOutput -join [Environment]::NewLine)
                                throw "certutil.exe failed (exit code $($addResult.ExitCode)) while adding certificate to '$storeName' store. Output:${([Environment]::NewLine)}$details"
                        }

                }
        }
        finally {
                Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        }
}

function Add-CertificateToStore {
        param(
                [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
                [Parameter(Mandatory = $true)][ValidateSet('Root','CA','TrustedPublisher','TrustedPeople')][string]$StoreName
        )

        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($StoreName, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
        try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $existing = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $Certificate.Thumbprint, $false)
                if (-not $existing -or $existing.Count -eq 0) {
                        $store.Add($Certificate)
                        Write-Host ("Added {0} to LocalMachine\\{1}: {2}" -f $Certificate.Thumbprint, $StoreName, $Certificate.Subject)
                }
                else {
                        Write-Host ("Already present {0} in LocalMachine\\{1}: {2}" -f $Certificate.Thumbprint, $StoreName, $Certificate.Subject)
                }
        }
        finally {
                $store.Close()
        }
}

function Add-SignerCertsFromCatalogs {
        param(
                [Parameter(Mandatory = $true)][string[]]$CatalogPaths
        )

        foreach ($cat in $CatalogPaths) {
                if (-not $cat -or -not (Test-Path -LiteralPath $cat)) {
                        continue
                }

                $sig = Get-AuthenticodeSignature -LiteralPath $cat
                $cert = $sig.SignerCertificate
                if ($cert) {
                        Add-CertificateToStore -Certificate $cert -StoreName 'TrustedPublisher'
                        Add-CertificateToStore -Certificate $cert -StoreName 'TrustedPeople'
                }
                else {
                        Write-Host "Warning: no signer certificate found in catalog '$cat'."
                }
        }
}

function Ensure-TrustedRootsFromWindowsUpdate {
        $tmp = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $sstPath = Join-Path $tmp 'roots.sst'

        try {
                $genResult = Invoke-ExternalExe -FilePath 'certutil.exe' -ArgumentList @('-generateSSTFromWU', $sstPath) -DisplayName 'certutil generateSSTFromWU roots'
                $genResult.AllOutput | ForEach-Object { Write-Host $_ }
                if ($genResult.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $sstPath)) {
                        $details = ($genResult.AllOutput -join [Environment]::NewLine)
                        throw "certutil.exe failed to generate root SST from Windows Update (exit code $($genResult.ExitCode)). Output:${([Environment]::NewLine)}$details"
                }

                $addResult = Invoke-ExternalExe -FilePath 'certutil.exe' -ArgumentList @('/addstore', '-f', 'Root', $sstPath) -DisplayName 'certutil addstore Root (roots.sst)'
                $addResult.AllOutput | ForEach-Object { Write-Host $_ }
                if ($addResult.ExitCode -ne 0) {
                        $details = ($addResult.AllOutput -join [Environment]::NewLine)
                        throw "certutil.exe failed (exit code $($addResult.ExitCode)) while importing Windows Update roots into 'Root' store. Output:${([Environment]::NewLine)}$details"
                }
        }
        finally {
                Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        }
}

function Get-InfCatalogPath {
        param(
                [Parameter(Mandatory = $true)][string]$InfPath
        )

        if (-not (Test-Path -LiteralPath $InfPath)) {
                throw "INF file was not found: '$InfPath'"
        }

        $catalogFile = $null
        foreach ($line in (Get-Content -LiteralPath $InfPath -ErrorAction SilentlyContinue)) {
                if ($line -match '(?i)^\s*CatalogFile(?:\.[^=]+)?\s*=\s*([^\s;]+)') {
                        $catalogFile = $Matches[1]
                        break
                }
        }

        if ($catalogFile) {
                return (Join-Path (Split-Path -Parent $InfPath) $catalogFile)
        }

        return [IO.Path]::ChangeExtension($InfPath, '.cat')
}

Assert-CommandExists -Name 'pnputil.exe'
Assert-CommandExists -Name 'certutil.exe'
Assert-CommandExists -Name '7z'
$downloadArgs = @{
        packageName = $Env:ChocolateyPackageName
        fileFullPath = $isoPath
        url = 'https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.285-1/virtio-win.iso'
        checksumType = 'sha512'
        checksum = '4f13070cc9241fa342deab4ebfac360565030580ff77b6e5f1951a64627621e5da4abfd30e1e46ca8bae2bb7dd4ff98141aff424142c9629a5876a61283962e5'
}
Get-ChocolateyWebFile @downloadArgs
$extractPath = Join-Path $pkgDir virtio
$extractResult = Invoke-ExternalExe -FilePath '7z' -ArgumentList @('x', $isoPath, "-o$extractPath") -DisplayName '7z extract virtio.iso'
$extractResult.AllOutput | ForEach-Object { Write-Host $_ }
if ($extractResult.ExitCode -ne 0) {
        throw "7z extraction failed (exit code $($extractResult.ExitCode)) for '$isoPath'."
}
Remove-Item $isoPath

$info = ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $extractPath 'data/info.json')))
$arch = if ($Env:PROCESSOR_ARCHITEW6432 -eq $null) { $Env:PROCESSOR_ARCHITECTURE } else { $Env:PROCESSOR_ARCHITEW6432 }
$os = switch ($Env:OS_NAME) {
        'Windows 11' { 'w11' }
        'Windows 10' { 'w10' }
        'Windows 8.1' { 'w8.1' }
        'Windows 8' { 'w8' }
        'Windows 7' { 'w7' }
        'Windows XP' { 'xp' }
        'Windows Server 2022' { '2k22' }
        'Windows Server 2019' { '2k19' }
        'Windows Server 2016' { '2k16' }
        'Windows Server 2012 R2' { '2k12R2' }
        'Windows Server 2012' { '2k12' }
        'Windows Server 2008 R2' { '2k8R2' }
        'Windows Server 2008' { '2k8' }
        'Windows Server 2003' { '2k3' }
}

if (-not $os) {
        throw "Unsupported or missing OS_NAME '$($Env:OS_NAME)'. Cannot select matching VirtIO drivers."
}

# NetKVM is available for all $infRelPath - we extract the signing chain from its catalog (.cat)
$netkvm = $info.drivers | where { $_.name -eq 'Red Hat VirtIO Ethernet Adapter' -and $_.arch -eq $arch -and $_.windows_version -eq $os } | Select-Object -First 1
if (-not $netkvm) {
        throw "Could not locate NetKVM driver entry for arch '$arch' and OS '$os' in info.json."
}

$netkvmCat = [IO.Path]::ChangeExtension((Join-Path $extractPath $netkvm.inf_path), '.cat')
Install-CatalogCertificateChain -CatalogPath $netkvmCat

# Pre-trust publishers for all selected driver catalogs before installing any drivers.
$selectedCatalogs = @(
        $info.drivers |
                where { $_.arch -eq $arch -and $_.windows_version -eq $os } |
                ForEach-Object {
                        $infPath = Join-Path $extractPath $_.inf_path
                        try { Get-InfCatalogPath -InfPath $infPath } catch { $null }
                } |
                Where-Object { $_ -and (Test-Path -LiteralPath $_) }
)
if ($selectedCatalogs -and $selectedCatalogs.Count -gt 0) {
        Add-SignerCertsFromCatalogs -CatalogPaths $selectedCatalogs
}

$infListPath = Join-Path $pkgDir inflist.txt
$info.drivers | where { $_.arch -eq $arch -and $_.windows_version -eq $os } | % {
        $infPath = Join-Path $extractPath $_.inf_path

        # Some driver packages may be signed with a different chain; install the chain for each INF's catalog.
        $catPath = $null
        try {
                $catPath = Get-InfCatalogPath -InfPath $infPath
                if ($catPath -and (Test-Path -LiteralPath $catPath)) {
                        Install-CatalogCertificateChain -CatalogPath $catPath
                }
        }
        catch {
                Write-Host "Warning: failed to install catalog certificate chain for '$infPath'. $_"
        }

        $pnpResult = Invoke-ExternalExe -FilePath 'pnputil.exe' -ArgumentList @('/add-driver', $infPath, '/install') -DisplayName "pnputil add-driver ($($_.name))"
        $pnpResult.AllOutput | ForEach-Object { Write-Host $_ }

        if ($pnpResult.ExitCode -ne 0) {
                # CERT_E_UNTRUSTEDROOT (0x800B0109) is common on images without an updated root store.
                if ($pnpResult.ExitCode -eq -2146762487) {
                        Write-Host 'pnputil reported CERT_E_UNTRUSTEDROOT; attempting to refresh Windows root certificates and retry once...'
                        Ensure-TrustedRootsFromWindowsUpdate

                        if ($catPath -and (Test-Path -LiteralPath $catPath)) {
                                Install-CatalogCertificateChain -CatalogPath $catPath
                        }

                        $retry = Invoke-ExternalExe -FilePath 'pnputil.exe' -ArgumentList @('/add-driver', $infPath, '/install') -DisplayName "pnputil add-driver retry ($($_.name))"
                        $retry.AllOutput | ForEach-Object { Write-Host $_ }
                        $pnpResult = $retry
                }

                if ($pnpResult.ExitCode -ne 0) {
                        $details = ($pnpResult.AllOutput -join [Environment]::NewLine)
                        throw "pnputil.exe failed (exit code $($pnpResult.ExitCode)) while installing driver '$($_.name)' from '$infPath'. Output:${([Environment]::NewLine)}$details"
                }
        }

        $publishedName = Get-PnpPublishedName -OutputLines @($pnpResult.AllOutput)
        if ($publishedName) {
                Add-Content -Path $infListPath -Value $publishedName
        }
        if ($_.name -eq 'VirtIO Balloon Driver') {
                $srcBln = Join-Path (Split-Path -Parent $infPath) 'blnsvr.exe'
                if (-not (Test-Path -LiteralPath $srcBln)) {
                        throw "Expected balloon service binary was not found: '$srcBln'"
                }

                $dstBln = Join-Path $pkgDir 'blnsvr.exe'
                Copy-Item -Force -LiteralPath $srcBln -Destination $dstBln

                $blnResult = Invoke-ExternalExe -FilePath $dstBln -ArgumentList @('-i') -DisplayName 'blnsvr install'
                $blnResult.AllOutput | ForEach-Object { Write-Host $_ }
                if ($blnResult.ExitCode -ne 0) {
                        $details = ($blnResult.AllOutput -join [Environment]::NewLine)
                        throw "blnsvr.exe failed (exit code $($blnResult.ExitCode)) during install (-i). Output:${([Environment]::NewLine)}$details"
                }
        }
}

$gaPath = Join-Path $extractPath 'guest-agent\qemu-ga-{0}.msi'
$installArgs = @{
        packageName = "QEMU Guest Agent"
        fileType = 'msi'
        silentArgs = '/qn /norestart'
        file = $gaPath -f 'i386'
        file64 = $gaPath -f 'x86_64'
}
Install-ChocolateyInstallPackage @installArgs

# Remove read-only attribute using attrib command before deletion
& attrib -r "$extractPath\*.*" /s /d
Remove-Item -Recurse -Force $extractPath