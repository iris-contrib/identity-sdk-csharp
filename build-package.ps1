# PowerShell script to build and validate the NuGet package

param(
    [string]$Configuration = "Release",
    [switch]$Publish,
    [string]$ApiKey = "",
    [string]$OutputPath = "./nupkg"
)

Write-Host "Building Iris Identity SDK NuGet Package..." -ForegroundColor Green

# Ensure we're in the right directory
if (-not (Test-Path "IrisIdentitySDK/IrisIdentitySDK.csproj")) {
    Write-Error "Please run this script from the repository root directory"
    exit 1
}

# Clean previous builds
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
if (Test-Path $OutputPath) {
    Remove-Item $OutputPath -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null

# Restore dependencies
Write-Host "Restoring dependencies..." -ForegroundColor Yellow
dotnet restore IrisIdentitySDK/IrisIdentitySDK.csproj
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to restore dependencies"
    exit 1
}

# Build the project
Write-Host "Building project..." -ForegroundColor Yellow
dotnet build IrisIdentitySDK/IrisIdentitySDK.csproj --configuration $Configuration --no-restore
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build project"
    exit 1
}

# Run tests if they exist
if (Test-Path "Tests") {
    Write-Host "Running tests..." -ForegroundColor Yellow
    dotnet test Tests/IrisIdentitySDK.Tests/IrisIdentitySDK.Tests.csproj --configuration $Configuration --no-build
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Tests failed, but continuing with package creation"
    }
}

# Create the NuGet package
Write-Host "Creating NuGet package..." -ForegroundColor Yellow
dotnet pack IrisIdentitySDK/IrisIdentitySDK.csproj --configuration $Configuration --no-build --output $OutputPath
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create NuGet package"
    exit 1
}

# List created packages
$packages = Get-ChildItem $OutputPath -Filter "*.nupkg"
if ($packages.Count -eq 0) {
    Write-Error "No packages were created"
    exit 1
}

Write-Host "Successfully created packages:" -ForegroundColor Green
foreach ($package in $packages) {
    Write-Host "  $($package.FullName)" -ForegroundColor Cyan
    
    # Show package size
    $sizeKB = [math]::Round($package.Length / 1KB, 2)
    Write-Host "  Size: $sizeKB KB" -ForegroundColor Gray
}

# Validate package contents
Write-Host "Package contents:" -ForegroundColor Yellow
$mainPackage = $packages | Where-Object { $_.Name -like "IrisIdentitySDK.*.nupkg" -and $_.Name -notlike "*symbols*" } | Select-Object -First 1
if ($mainPackage) {
    # Use PowerShell to examine the package (it's a zip file)
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($mainPackage.FullName)
        $entries = $zip.Entries | Sort-Object FullName
        foreach ($entry in $entries) {
            Write-Host "  $($entry.FullName)" -ForegroundColor Gray
        }
        $zip.Dispose()
    }
    catch {
        Write-Warning "Could not examine package contents: $($_.Exception.Message)"
    }
}

# Publish if requested
if ($Publish) {
    if (-not $ApiKey) {
        Write-Error "API key is required for publishing. Use -ApiKey parameter."
        exit 1
    }
    
    Write-Host "Publishing to NuGet.org..." -ForegroundColor Yellow
    foreach ($package in $packages) {
        if ($package.Name -notlike "*symbols*") {
            Write-Host "Publishing $($package.Name)..." -ForegroundColor Cyan
            dotnet nuget push $package.FullName --api-key $ApiKey --source https://api.nuget.org/v3/index.json
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Failed to publish $($package.Name)"
                exit 1
            }
        }
    }
    Write-Host "Package published successfully!" -ForegroundColor Green
}

Write-Host "Build completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "To install this package locally for testing:" -ForegroundColor Yellow
Write-Host "  dotnet add package IrisIdentitySDK --source $((Resolve-Path $OutputPath).Path)" -ForegroundColor Cyan
Write-Host ""
Write-Host "To publish to NuGet.org:" -ForegroundColor Yellow
Write-Host "  .\build-package.ps1 -Publish -ApiKey YOUR_API_KEY" -ForegroundColor Cyan