#!/usr/bin/env python3
"""
Security Check Script - Vérifie qu'aucun secret ne sera pushé sur GitHub
"""

import os
import sys
from pathlib import Path

def check_security():
    """Vérifier que les fichiers sensibles ne seront pas commités."""
    
    print("=" * 70)
    print("SECURITY CHECK - Verification before GitHub Push")
    print("=" * 70)
    print()
    
    project_root = Path.cwd()
    issues = []
    warnings = []
    
    # 1. Vérifier .env
    print("1. Verify .env...")
    env_file = project_root / ".env"
    if env_file.exists():
        issues.append("[ERROR] .env exists! Must NOT be in repo")
    else:
        print("   [OK] .env does not exist (good)")
    
    env_example = project_root / ".env.example"
    if env_example.exists():
        print("   [OK] .env.example exists (template provided)")
    else:
        warnings.append("[WARN] .env.example does not exist")
    
    # 2. Vérifier .gitignore
    print("\n2. Verify .gitignore...")
    gitignore = project_root / ".gitignore"
    if gitignore.exists():
        with open(gitignore, 'r') as f:
            content = f.read().lower()
            
        required_patterns = [
            ('.env', '.env doit être ignoré'),
            ('__pycache__', '__pycache__ doit être ignoré'),
            ('venv', 'venv doit être ignoré'),
            ('.idea', 'IDE config doit être ignoré'),
            ('*.pyc', '*.pyc files doit être ignoré'),
            ('*.log', 'Log files doivent être ignorés'),
        ]
        
        for pattern, description in required_patterns:
            if pattern.lower() in content:
                print(f"   [OK] {description}")
            else:
                warnings.append(f"[WARN] {description} - pattern '{pattern}' not found")
    else:
        issues.append("[ERROR] .gitignore missing!")
    
    # 3. Vérifier les fichiers credentials
    print("\n3. Check credential files...")
    sensitive_files = [
        'credentials.json',
        'secrets.json',
        'aws_keys.txt',
        'api_keys.txt',
        'config.local.py',
    ]
    
    found_sensitive = []
    for fname in sensitive_files:
        fpath = project_root / fname
        if fpath.exists():
            found_sensitive.append(fname)
    
    if found_sensitive:
        issues.append(f"[ERROR] Sensitive files found: {', '.join(found_sensitive)}")
    else:
        print("   [OK] No credential files found")
    
    # 4. Vérifier si .git existe
    print("\n4. Verify git...")
    git_dir = project_root / ".git"
    if git_dir.exists():
        print("   [OK] Git is initialized")
        
        # Vérifier le remote
        try:
            import subprocess
            result = subprocess.run(
                ['git', 'remote', '-v'],
                capture_output=True,
                text=True,
                cwd=project_root
            )
            if result.stdout:
                print("   [OK] Git remote configured")
            else:
                warnings.append("[WARN] Git remote not configured - run 'git remote add origin ...'")
        except Exception as e:
            warnings.append(f"[WARN] Unable to verify remote: {e}")
    else:
        warnings.append("[WARN] Git not initialized (run 'git init' before pushing)")
    
    # 5. Vérifier les API keys hardcodées dans le code
    print("\n5. Check for hardcoded API keys in code...")
    python_files = list(project_root.glob("**/*.py"))
    api_key_patterns = [
        'api_key = "',
        'API_KEY = "',
        'secret_key = "',
        'SECRET_KEY = "',
        'password = "',
        'PASSWORD = "',
    ]
    
    found_keys = False
    for py_file in python_files:
        # Skip __pycache__, virtualenv/site-packages directories, and this script file
        s = str(py_file).lower()
        if py_file.name == 'security_check.py':
            continue
        if '__pycache__' in s or 'site-packages' in s or '\\venv\\' in s or '\\.venv\\' in s or '/venv/' in s or '/.venv/' in s or '\\env\\' in s:
            continue
            
        try:
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for pattern in api_key_patterns:
                    if pattern in content:
                        # C'est probablement du template, pas un vrai secret
                        if '.example' not in str(py_file):
                            issues.append(f"[ERROR] Pattern '{pattern}' found hardcoded in {py_file}")
                            found_keys = True
        except Exception as e:
            pass
    
    if not found_keys:
        print("   [OK] No hardcoded API keys found in code")
    
    # 6. Résumé
    print("\n" + "=" * 70)
    
    if issues:
        print("\n[ERROR] CRITICAL ISSUES (must fix):")
        for issue in issues:
            print(f"  {issue}")
    
    if warnings:
        print("\n[WARN] WARNINGS:")
        for warning in warnings:
            print(f"  {warning}")
    
    if not issues and not warnings:
        print("\n[OK] ALL CLEAR")
        print("   No secrets detected")
        print("   .gitignore looks correct")
        print("   Ready to push to GitHub")
    
    print("\n" + "=" * 70)
    
    # Retourner 0 si pas d'erreurs, 1 sinon
    return 1 if issues else 0

if __name__ == "__main__":
    sys.exit(check_security())
