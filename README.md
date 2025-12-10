# Chocolatey VirtIO Drivers Package

Automated Chocolatey package for VirtIO drivers.

## Updating the Version

### Method 1: Local Update (Recommended)

Run the update script locally to update all files:

```powershell
.\update-version.ps1 -VirtioVersion "0.1.285-1"
```

Then commit and push:

```bash
git add virtio-drivers.nuspec tools/chocolateyinstall.ps1
git commit -m "Update to version 0.1.285-1"
git tag 0.1.285-1
git push origin main --tags
```

### Method 2: Tag Only

Create and push a tag matching the upstream VirtIO version:

```bash
git tag 0.1.285-1
git push origin 0.1.285-1
```

GitHub Actions will automatically:
- Download the ISO and calculate the checksum
- Update the `.nuspec` and install script with the new version
- Build the Chocolatey package with version `0.1.285.1`
- Publish to Chocolatey Community Repository (if `CHOCO_API_KEY` secret is configured)

## GitHub Secrets

To enable automatic publishing, add your Chocolatey API key as a repository secret:

1. Go to repository Settings → Secrets and variables → Actions
2. Create a new secret named `CHOCO_API_KEY`
3. Add your Chocolatey API key (get it from https://community.chocolatey.org/account)

## Manual Build

To build the package locally:

```powershell
choco pack virtio-drivers.nuspec
```

## Version Configuration

All version information is centralized in `version.json`:
- `version`: Chocolatey package version
- `virtio_version`: VirtIO release version
- `url`: Download URL for the ISO
- `checksum`: SHA512 checksum
- `checksumType`: Hash algorithm (sha512)
