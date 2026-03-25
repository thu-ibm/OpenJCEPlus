#!/usr/bin/env pwsh
# PowerShell script to format all C/C++ files using clang-format
# Usage: powershell -ExecutionPolicy Bypass -File format-native-code.ps1

Write-Host "`n=== OpenJCEPlus Native Code Formatter ===" -ForegroundColor Cyan
Write-Host "Using .clang-format rules from project root`n" -ForegroundColor Gray

# Check if clang-format is available
$clangFormat = Get-Command clang-format -ErrorAction SilentlyContinue
if (-not $clangFormat) {
    Write-Host "ERROR: clang-format not found!" -ForegroundColor Red
    Write-Host "Please install LLVM or clang-format:" -ForegroundColor Yellow
    Write-Host "  - Download from: https://releases.llvm.org/" -ForegroundColor Yellow
    Write-Host "  - Or use Chocolatey: choco install llvm" -ForegroundColor Yellow
    exit 1
}

Write-Host "Found: $($clangFormat.Source)" -ForegroundColor Green
Write-Host "Version: $(clang-format --version)`n" -ForegroundColor Green

# Get all C/C++ files
Write-Host "Scanning for C/C++ files..." -ForegroundColor Cyan
$files = Get-ChildItem -Path src/main/native -Include *.c,*.h -Recurse

if ($files.Count -eq 0) {
    Write-Host "No C/C++ files found!" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($files.Count) files to format`n" -ForegroundColor Green

# Format each file
$formatted = 0
$errors = 0

foreach ($file in $files) {
    $relativePath = $file.FullName.Replace((Get-Location).Path + "\", "")
    Write-Host "Formatting: $relativePath" -ForegroundColor Gray
    
    try {
        clang-format -i $file.FullName
        if ($LASTEXITCODE -eq 0) {
            $formatted++
        } else {
            $errors++
            Write-Host "  ERROR: Failed to format" -ForegroundColor Red
        }
    } catch {
        $errors++
        Write-Host "  ERROR: $_" -ForegroundColor Red
    }
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Successfully formatted: $formatted files" -ForegroundColor Green
if ($errors -gt 0) {
    Write-Host "Errors: $errors files" -ForegroundColor Red
    exit 1
} else {
    Write-Host "All files formatted successfully!" -ForegroundColor Green
    exit 0
}


