#!/usr/bin/env pwsh
# PowerShell script to check C/C++ formatting without modifying files
# Usage: powershell -ExecutionPolicy Bypass -File check-formatting.ps1

Write-Host "`n=== OpenJCEPlus Formatting Checker ===" -ForegroundColor Cyan
Write-Host "Checking code against .clang-format rules`n" -ForegroundColor Gray

# Check if clang-format is available
$clangFormat = Get-Command clang-format -ErrorAction SilentlyContinue
if (-not $clangFormat) {
    Write-Host "ERROR: clang-format not found!" -ForegroundColor Red
    Write-Host "Please install LLVM or clang-format" -ForegroundColor Yellow
    exit 1
}

Write-Host "Using: $($clangFormat.Source)" -ForegroundColor Green
Write-Host "Version: $(clang-format --version)`n" -ForegroundColor Green

# Get all C/C++ files
Write-Host "Scanning for C/C++ files..." -ForegroundColor Cyan
$files = Get-ChildItem -Path src/main/native -Include *.c,*.h -Recurse

if ($files.Count -eq 0) {
    Write-Host "No C/C++ files found!" -ForegroundColor Yellow
    exit 0
}

Write-Host "Checking $($files.Count) files`n" -ForegroundColor Green

# Check each file
$needsFormatting = @()
$checked = 0

foreach ($file in $files) {
    $relativePath = $file.FullName.Replace((Get-Location).Path + "\", "")
    Write-Host "Checking: $relativePath" -ForegroundColor Gray
    
    # Run clang-format in dry-run mode
    $result = clang-format --dry-run --Werror $file.FullName 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        $needsFormatting += $relativePath
        Write-Host "  [X] Needs formatting" -ForegroundColor Yellow
    } else {
        Write-Host "  [OK] Properly formatted" -ForegroundColor Green
    }
    $checked++
}

# Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
Write-Host "Files checked: $checked" -ForegroundColor Gray

if ($needsFormatting.Count -gt 0) {
    Write-Host "`nFiles needing formatting: $($needsFormatting.Count)" -ForegroundColor Yellow
    Write-Host "`nList of files:" -ForegroundColor Yellow
    foreach ($file in $needsFormatting) {
        Write-Host "  - $file" -ForegroundColor Yellow
    }
    
    Write-Host "`nTo fix, run:" -ForegroundColor Cyan
    Write-Host "  powershell -ExecutionPolicy Bypass -File format-native-code.ps1" -ForegroundColor White
    Write-Host "`nOr format individual files:" -ForegroundColor Cyan
    Write-Host "  clang-format -i FILENAME" -ForegroundColor White
    
    exit 1
} else {
    Write-Host "`nAll files are properly formatted!" -ForegroundColor Green
    exit 0
}


