# Publishing Iris Identity SDK to NuGet

This guide explains how to publish the Iris Identity SDK as a NuGet package.

## Prerequisites

1. **NuGet Account**: Create an account at [nuget.org](https://www.nuget.org/)
2. **API Key**: Generate an API key from your NuGet profile
3. **.NET 8.0 SDK**: Ensure you have .NET 8.0 SDK installed
4. **NuGet CLI**: Install the latest NuGet CLI tools

## Package Configuration

The project is already configured for NuGet publishing in `IrisIdentitySDK/IrisIdentitySDK.csproj`:

- ✅ Package ID: `IrisIdentitySDK`
- ✅ Version: `1.0.0`
- ✅ Authors and company information
- ✅ License: MIT
- ✅ Description and tags
- ✅ Repository URLs
- ✅ README.md included

## Build and Pack

### Option 1: Automatic Build (Recommended)

The project has `GeneratePackageOnBuild` set to `true`, so building the project automatically creates the NuGet package:

```bash
# Navigate to the SDK project directory
cd IrisIdentitySDK

# Build the project (this will create the .nupkg file)
dotnet build --configuration Release
```

The package will be created at: `IrisIdentitySDK/bin/Release/IrisIdentitySDK.1.0.0.nupkg`

### Option 2: Manual Pack

```bash
# Navigate to the SDK project directory
cd IrisIdentitySDK

# Create the package manually
dotnet pack --configuration Release --output ./nupkg
```

## Validate Package

Before publishing, validate the package contents:

```bash
# Install NuGet package explorer (optional)
dotnet tool install -g NuGetPackageExplorer

# Or use command line to inspect
nuget verify IrisIdentitySDK.1.0.0.nupkg
```

## Publish to NuGet

### Step 1: Set up API Key

```bash
# Set your NuGet API key (replace with your actual key)
nuget setapikey YOUR_API_KEY_HERE -source https://api.nuget.org/v3/index.json
```

### Step 2: Publish the Package

```bash
# Navigate to where the .nupkg file is located
cd IrisIdentitySDK/bin/Release

# Push to NuGet (replace with actual filename if version differs)
dotnet nuget push IrisIdentitySDK.1.0.0.nupkg --api-key YOUR_API_KEY_HERE --source https://api.nuget.org/v3/index.json
```

### Alternative using NuGet CLI

```bash
nuget push IrisIdentitySDK.1.0.0.nupkg YOUR_API_KEY_HERE -Source https://api.nuget.org/v3/index.json
```

## Version Management

### For Future Updates

1. **Update Version**: Increment version in `IrisIdentitySDK.csproj`
   ```xml
   <Version>1.0.1</Version>
   <AssemblyVersion>1.0.1.0</AssemblyVersion>
   <FileVersion>1.0.1.0</FileVersion>
   ```

2. **Update Release Notes**:
   ```xml
   <PackageReleaseNotes>Bug fixes and improvements</PackageReleaseNotes>
   ```

3. **Rebuild and Republish**:
   ```bash
   dotnet build --configuration Release
   dotnet nuget push IrisIdentitySDK.1.0.1.nupkg --api-key YOUR_API_KEY_HERE --source https://api.nuget.org/v3/index.json
   ```

## Testing Installation

After publishing, test the package installation:

```bash
# Create a test project
dotnet new console -n TestProject
cd TestProject

# Install your package
dotnet add package IrisIdentitySDK

# Or specify version
dotnet add package IrisIdentitySDK --version 1.0.0
```

## Package Information

Once published, users can install the package using:

### Package Manager Console
```powershell
Install-Package IrisIdentitySDK
```

### .NET CLI
```bash
dotnet add package IrisIdentitySDK
```

### PackageReference
```xml
<PackageReference Include="IrisIdentitySDK" Version="1.0.0" />
```

## CI/CD Integration

### GitHub Actions Example

Create `.github/workflows/publish.yml`:

```yaml
name: Publish NuGet Package

on:
  release:
    types: [published]

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup .NET
      uses: actions/setup-dotnet@v3
      with:
        dotnet-version: '8.0.x'
    
    - name: Restore dependencies
      run: dotnet restore
    
    - name: Build
      run: dotnet build --configuration Release --no-restore
    
    - name: Test
      run: dotnet test --no-build --verbosity normal
    
    - name: Pack
      run: dotnet pack IrisIdentitySDK/IrisIdentitySDK.csproj --configuration Release --no-build --output ./nupkg
    
    - name: Publish to NuGet
      run: dotnet nuget push ./nupkg/*.nupkg --api-key ${{ secrets.NUGET_API_KEY }} --source https://api.nuget.org/v3/index.json
```

## Troubleshooting

### Common Issues

1. **Package Already Exists**: You cannot republish the same version. Increment the version number.

2. **API Key Issues**: Ensure your API key has the correct permissions and hasn't expired.

3. **Missing Dependencies**: Ensure all PackageReference dependencies are available on NuGet.

4. **README Not Showing**: Ensure the README.md path is correct in the project file.

### Package Validation

Use these tools to validate your package:

```bash
# Check package dependencies
dotnet list package --vulnerable --include-transitive

# Validate package structure
nuget verify IrisIdentitySDK.1.0.0.nupkg
```

## Security Considerations

- Never commit API keys to version control
- Use environment variables or CI/CD secrets for API keys
- Consider signing your packages for additional security
- Regularly update dependencies to patch security vulnerabilities

## Support

For issues with the SDK itself, please visit:
- GitHub Repository: https://github.com/iris-contrib/identity-sdk-csharp
- Iris Framework Documentation: https://iris-go.com