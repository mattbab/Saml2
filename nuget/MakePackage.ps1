$ErrorActionPreference = "Stop"

$status = (git status)
$clean = $status| select-string "working tree clean"

<#
if ("$clean" -eq "")
{
  echo "Working copy is not clean. Cannot proceed."
  exit
}

$master = $status | select-string "On branch master"

if ("$master" -eq "")
{
  echo "Releases are only allowed from the master branch."
  exit
}
#>

pushd ..
if (Test-Path "Sustainsys.Saml2\bin\Release")
{
	del Sustainsys.Saml2\bin\Release\*.dll
}
if (Test-Path "Sustainsys.Saml2.AspNetCore2\bin\Release")
{
	del Sustainsys.Saml2.AspNetCore2\bin\Release\*.dll
}
echo "Creating nuspec files..."

$releaseNotesContent="`n $((get-content nuget\ReleaseNotes.txt) -join "`n`")`n";
$releaseNotes = "<releaseNotes>" + $releaseNotesContent + "</releaseNotes>";
function Create-Nuspec($projectName)
{
    (gc nuget\$projectName.nuspec) | 
		% { $_ -replace "<releaseNotes />", $releaseNotes } |
		set-content $projectName\$projectName.nuspec
}

function Update-Csproj($projectName)
{
    (gc $projectName\$projectName.csproj) | 
		% { $_ -replace '\$releaseNotes\$', $releaseNotesContent } |
		set-content $projectName\$projectName.csproj
}

copy Sustainsys.Saml2\Sustainsys.Saml2.csproj Sustainsys.Saml2\Sustainsys.Saml2.csproj.bak
copy Sustainsys.Saml2.AspNetCore2\Sustainsys.Saml2.AspNetCore2.csproj Sustainsys.Saml2.AspNetCore2\Sustainsys.Saml2.AspNetCore2.csproj.bak
Update-Csproj("Sustainsys.Saml2")
Update-Csproj("Sustainsys.Saml2.AspNetCore2")

echo "Building packages..."

$version = [regex]::match((sls -Pattern AssemblyVersion .\VersionInfo.cs), '.*Version\("(.*)\".*').Groups[1].Value

dotnet pack -c Release -o nuget Sustainsys.Saml2\Sustainsys.Saml2.csproj /p:Version=$version
dotnet pack -c Release -o nuget Sustainsys.Saml2.AspNetCore2\Sustainsys.Saml2.AspNetCore2.csproj /p:Version=$version

copy Sustainsys.Saml2\Sustainsys.Saml2.csproj.bak Sustainsys.Saml2\Sustainsys.Saml2.csproj
del Sustainsys.Saml2\Sustainsys.Saml2.csproj.bak 
copy Sustainsys.Saml2.AspNetCore2\Sustainsys.Saml2.AspNetCore2.csproj.bak Sustainsys.Saml2.AspNetCore2\Sustainsys.Saml2.AspNetCore2.csproj
del Sustainsys.Saml2.AspNetCore2\Sustainsys.Saml2.AspNetCore2.csproj.bak 

popd
