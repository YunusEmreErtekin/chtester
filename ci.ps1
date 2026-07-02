# Yerel CI: GitHub Actions ile ayni adimlar (derle -> vet -> test).
# Kullanim:  pwsh ./ci.ps1   (veya)   powershell -File ci.ps1
$ErrorActionPreference = "Stop"

Write-Host "==> go build ./..." -ForegroundColor Cyan
go build ./...
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> ikililer (chtester / invoke-cleanup / aggregate / scope-sign)" -ForegroundColor Cyan
go build -o chtester.exe ./cmd/chtester;            if ($LASTEXITCODE -ne 0) { exit 1 }
go build -o invoke-cleanup.exe ./cmd/invoke-cleanup; if ($LASTEXITCODE -ne 0) { exit 1 }
go build -o chtester-aggregate.exe ./cmd/aggregate;  if ($LASTEXITCODE -ne 0) { exit 1 }
go build -o scope-sign.exe ./cmd/scope-sign;         if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> go vet -unsafeptr=false ./... (nativeapi COM/Win32 hariç)" -ForegroundColor Cyan
go vet -unsafeptr=false ./...
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==> go test ./..." -ForegroundColor Cyan
go test ./...
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "TUM ADIMLAR YESIL" -ForegroundColor Green
