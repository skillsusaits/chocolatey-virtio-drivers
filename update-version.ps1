# Script to update version configuration and template files
# Usage: .\update-version.ps1 -VirtioVersion "0.1.285-1"

param(
    [Parameter(Mandatory=$true)]
    [string]$VirtioVersion
)

# Calculate package version by converting hyphens to dots
$PackageVersion = $VirtioVersion.Replace('-', '.')

$url = "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-$VirtioVersion/virtio-win.iso"

Write-Host "Downloading ISO to calculate checksum..."
$tempFile = "virtio.iso"
Invoke-WebRequest -Uri $url -OutFile $tempFile

Write-Host "Calculating SHA512 checksum..."
$hash = Get-FileHash -Path $tempFile -Algorithm SHA512
$checksum = $hash.Hash.ToLower()

Remove-Item $tempFile

Write-Host "`nUpdating virtio-drivers.nuspec..."
$nuspecPath = "virtio-drivers.nuspec"
$content = Get-Content $nuspecPath -Raw
$content = $content -replace '<version>.*?</version>', "<version>$PackageVersion</version>"
Set-Content $nuspecPath $content

Write-Host "Updating tools/chocolateyinstall.ps1..."
$installPath = "tools/chocolateyinstall.ps1"
$content = Get-Content $installPath -Raw
$content = $content -replace "url = '.*?'", "url = '$url'"
$content = $content -replace "checksumType = '.*?'", "checksumType = 'sha512'"
$content = $content -replace "checksum = '.*?'", "checksum = '$checksum'"
Set-Content $installPath $content

Write-Host "`nVersion configuration updated successfully!"
Write-Host "Package Version: $PackageVersion"
Write-Host "VirtIO Version: $VirtioVersion"
Write-Host "URL: $url"
Write-Host "Checksum: $checksum"
Write-Host "`nFiles updated:"
Write-Host "  - virtio-drivers.nuspec"
Write-Host "  - tools/chocolateyinstall.ps1"
Write-Host "`nReady to commit and push!"
