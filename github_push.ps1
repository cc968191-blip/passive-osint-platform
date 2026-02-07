# GitHub Push Script - Passive OSINT Platform (PowerShell)
# Usage: .\github_push.ps1 -Message "Commit message" -Username "TON_USERNAME"

param(
    [string]$Message = "",
    [string]$Username = ""
)

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  🚀 Passive OSINT Platform - GitHub Push Script" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Vérifications
if ([string]::IsNullOrEmpty($Message)) {
    Write-Host "❌ Erreur: Message de commit requis" -ForegroundColor Red
    Write-Host "Usage: .\github_push.ps1 -Message 'Ton message' -Username 'TON_USERNAME'" -ForegroundColor Yellow
    exit 1
}

if ([string]::IsNullOrEmpty($Username)) {
    Write-Host "❌ Erreur: Username GitHub requis" -ForegroundColor Red
    Write-Host "Usage: .\github_push.ps1 -Message 'Ton message' -Username 'TON_USERNAME'" -ForegroundColor Yellow
    exit 1
}

$RepoName = "passive-osint-platform"

Write-Host "📋 Configuration:" -ForegroundColor Yellow
Write-Host "  • Commit message: $Message"
Write-Host "  • GitHub user: $Username"
Write-Host "  • Repository: $RepoName"
Write-Host ""

# Vérifier si .env existe
if (Test-Path ".env") {
    Write-Host "⚠️  Attention: .env trouvé dans le répertoire!" -ForegroundColor Yellow
    Write-Host "❌ DANGER: .env ne doit PAS être en repo!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Les fichiers sensibles doivent être exclus:" -ForegroundColor Yellow
    Write-Host "  • .env (clés API)"
    Write-Host "  • __pycache__/ (optimisé)"
    Write-Host "  • venv/ (dépendances)"
    Write-Host ""
    
    $response = Read-Host "Continuer quand même? (y/N)"
    if ($response -ne "y" -and $response -ne "Y") {
        Write-Host "❌ Annulé." -ForegroundColor Red
        exit 1
    }
}

# STEP 1: Vérifier le status git
Write-Host "1️⃣  Vérifier le status Git..." -ForegroundColor Cyan
git status
Write-Host ""

# STEP 2: Ajouter les fichiers
Write-Host "2️⃣  Ajouter les fichiers..." -ForegroundColor Cyan
git add .
Write-Host ""

# STEP 3: Vérifier quels fichiers seront commités
Write-Host "3️⃣  Vérifier quels fichiers seront commités..." -ForegroundColor Cyan
git status
Write-Host ""

$confirm = Read-Host "4️⃣  Confirmer et continuer? (y/N)"
if ($confirm -ne "y" -and $confirm -ne "Y") {
    Write-Host "❌ Annulé." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "5️⃣  Commit..." -ForegroundColor Cyan
git commit -m "$Message"

Write-Host ""
Write-Host "6️⃣  Vérifier la branche..." -ForegroundColor Cyan
$CurrentBranch = git rev-parse --abbrev-ref HEAD
Write-Host "  Branch actuelle: $CurrentBranch"

if ($CurrentBranch -ne "main") {
    Write-Host "⚠️  Warning: Tu n'es pas sur la branche 'main'" -ForegroundColor Yellow
    $changeBranch = Read-Host "Changer vers 'main'? (y/N)"
    if ($changeBranch -eq "y" -or $changeBranch -eq "Y") {
        git checkout main
    }
}

Write-Host ""
Write-Host "7️⃣  Vérifier le remote..." -ForegroundColor Cyan
$RemoteUrl = git remote get-url origin 2>$null
if ($null -eq $RemoteUrl) {
    $RemoteUrl = "NOT SET"
}
Write-Host "  Remote: $RemoteUrl"

if ($RemoteUrl -eq "NOT SET") {
    Write-Host ""
    Write-Host "🔧 Configurer le remote..." -ForegroundColor Cyan
    $RepoUrl = "https://github.com/$Username/$RepoName.git"
    Write-Host "  Setting: $RepoUrl"
    git remote add origin $RepoUrl
}

Write-Host ""
Write-Host "8️⃣  Push vers GitHub..." -ForegroundColor Cyan
git push -u origin main

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "✅ Succès! Ton code est sur GitHub!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "🔗 Voir ton repo:" -ForegroundColor Yellow
Write-Host "   https://github.com/$Username/$RepoName"
Write-Host ""
Write-Host "📝 Prochaines étapes:" -ForegroundColor Yellow
Write-Host "  1. Ajouter le lien à ton portefolio"
Write-Host "  2. Créer une release: https://github.com/$Username/$RepoName/releases"
Write-Host "  3. Tester le clone: git clone https://github.com/$Username/$RepoName"
Write-Host ""
