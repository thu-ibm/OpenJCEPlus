#!/usr/bin/env pwsh
# PowerShell script to format C/C++ files one at a time with confirmation
# Usage: powershell -ExecutionPolicy Bypass -File format-one-file.ps1

param(
    [string]$FilePath = ""
)

Write-Host "`n=== OpenJCEPlus Single File Formatter ===" -ForegroundColor Cyan
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

# If file path provided as argument, format it directly
if ($FilePath -ne "") {
    if (-not (Test-Path $FilePath)) {
        Write-Host "ERROR: File not found: $FilePath" -ForegroundColor Red
        exit 1
    }
    
    Write-Host "Formatting: $FilePath" -ForegroundColor Cyan
    clang-format -i $FilePath
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Successfully formatted!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host "ERROR: Failed to format file" -ForegroundColor Red
        exit 1
    }
}

# Interactive mode: Get all C/C++ files
Write-Host "Scanning for C/C++ files..." -ForegroundColor Cyan
$files = Get-ChildItem -Path src/main/native -Include *.c,*.h -Recurse

if ($files.Count -eq 0) {
    Write-Host "No C/C++ files found!" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($files.Count) files`n" -ForegroundColor Green

# Process each file with confirmation
$formatted = 0
$skipped = 0
$errors = 0

foreach ($file in $files) {
    $relativePath = $file.FullName.Replace((Get-Location).Path + "\", "")
    
    Write-Host "`n----------------------------------------" -ForegroundColor Gray
    Write-Host "File: $relativePath" -ForegroundColor Cyan
    
    # Check if file needs formatting
    $needsFormatting = $false
    $result = clang-format --dry-run --Werror $file.FullName 2>&1
    if ($LASTEXITCODE -ne 0) {
        $needsFormatting = $true
        Write-Host "Status: Needs formatting" -ForegroundColor Yellow
    } else {
        Write-Host "Status: Already properly formatted" -ForegroundColor Green
    }
    
    # Ask user what to do
    Write-Host "`nOptions:" -ForegroundColor White
    Write-Host "  [F] Format this file" -ForegroundColor White
    Write-Host "  [S] Skip this file" -ForegroundColor White
    Write-Host "  [V] View diff (what would change)" -ForegroundColor White
    Write-Host "  [Q] Quit" -ForegroundColor White
    
    $choice = Read-Host "`nYour choice (F/S/V/Q)"
    
    switch ($choice.ToUpper()) {
        "F" {
            Write-Host "Formatting..." -ForegroundColor Cyan
            clang-format -i $file.FullName
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully formatted!" -ForegroundColor Green
                $formatted++
            } else {
                Write-Host "ERROR: Failed to format" -ForegroundColor Red
                $errors++
            }
        }
        "S" {
            Write-Host "Skipped" -ForegroundColor Gray
            $skipped++
        }
        "V" {
            Write-Host "`nShowing diff (what would change):" -ForegroundColor Cyan
            Write-Host "----------------------------------------" -ForegroundColor Gray
            
            # Get formatted version
            $formatted_content = clang-format $file.FullName
            $original_content = Get-Content $file.FullName -Raw
            
            if ($formatted_content -eq $original_content) {
                Write-Host "No changes needed - file is already properly formatted" -ForegroundColor Green
            } else {
                Write-Host "File would be reformatted (showing first 20 lines of diff)" -ForegroundColor Yellow
                
                # Simple diff display
                $formattedLines = $formatted_content -split "`n"
                $originalLines = $original_content -split "`n"
                
                $lineNum = 1
                $diffCount = 0
                for ($i = 0; $i -lt [Math]::Min($formattedLines.Count, $originalLines.Count) -and $diffCount -lt 20; $i++) {
                    if ($formattedLines[$i] -ne $originalLines[$i]) {
                        Write-Host "Line $($i+1):" -ForegroundColor Yellow
                        Write-Host "  - $($originalLines[$i])" -ForegroundColor Red
                        Write-Host "  + $($formattedLines[$i])" -ForegroundColor Green
                        $diffCount++
                    }
                }
                
                if ($diffCount -eq 20) {
                    Write-Host "... (more changes not shown)" -ForegroundColor Gray
                }
            }
            
            Write-Host "----------------------------------------" -ForegroundColor Gray
            
            # Ask again after showing diff
            $choice2 = Read-Host "`nFormat this file? (Y/N)"
            if ($choice2.ToUpper() -eq "Y") {
                Write-Host "Formatting..." -ForegroundColor Cyan
                clang-format -i $file.FullName
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "Successfully formatted!" -ForegroundColor Green
                    $formatted++
                } else {
                    Write-Host "ERROR: Failed to format" -ForegroundColor Red
                    $errors++
                }
            } else {
                Write-Host "Skipped" -ForegroundColor Gray
                $skipped++
            }
        }
        "Q" {
            Write-Host "`nQuitting..." -ForegroundColor Yellow
            break
        }
        default {
            Write-Host "Invalid choice, skipping file" -ForegroundColor Yellow
            $skipped++
        }
    }
}

# Summary
Write-Host "`n========================================"  -ForegroundColor Cyan
Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "========================================"  -ForegroundColor Cyan
Write-Host "Files formatted: $formatted" -ForegroundColor Green
Write-Host "Files skipped: $skipped" -ForegroundColor Gray
if ($errors -gt 0) {
    Write-Host "Errors: $errors" -ForegroundColor Red
}
Write-Host ""

if ($errors -gt 0) {
    exit 1
} else {
    exit 0
}

# Made with Bob
