param(
    [string]$JavaHome = "$env:ProgramFiles\Java\jdk-21",
    [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath "$JavaHome\bin\java.exe")) { throw 'Provide a compatible JDK using -JavaHome.' }
if (-not (Test-Path -LiteralPath "$SdkRoot\platforms\android-35\android.jar")) { throw 'Android SDK platform 35 is required.' }
if (-not (Test-Path -LiteralPath "$SdkRoot\ndk\27.0.12077973\source.properties")) { throw 'Android NDK 27.0.12077973 is required.' }
if (-not (Test-Path -LiteralPath "$SdkRoot\cmake\3.22.1\bin\cmake.exe")) { throw 'Android SDK CMake 3.22.1 is required.' }
$previousJavaHome = $env:JAVA_HOME
$previousAndroidHome = $env:ANDROID_HOME
try {
    $env:JAVA_HOME = $JavaHome
    $env:ANDROID_HOME = $SdkRoot
    & "$PSScriptRoot\..\gradlew.bat" -p "$PSScriptRoot\.." :probe:assembleDebug :module:assembleDebug :rawprobe:assembleDebug :procprobe:assembleDebug :attestationprobe:assembleDebug :probe:lintDebug :module:lintDebug :rawprobe:lintDebug :procprobe:lintDebug :attestationprobe:lintDebug --max-workers=2 --console=plain
    if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }
} finally {
    $env:JAVA_HOME = $previousJavaHome
    $env:ANDROID_HOME = $previousAndroidHome
}
