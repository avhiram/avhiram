#!/usr/bin/env python3
"""
Jekyll Liquid Syntax Fixer

Ce script identifie et corrige les erreurs de syntaxe Liquid dans les fichiers markdown Jekyll,
notamment celles liées aux doubles accolades qui sont interprétées comme des balises Liquid.

Usage:
    python jekyll_liquid_fixer.py <file_path>
    
Exemple:
    python jekyll_liquid_fixer.py _posts/2025-05-18-cpts.md
"""

import re
import sys
import os
import argparse

def fix_liquid_syntax(file_path, backup=True):
    """
    Corrige les erreurs de syntaxe Liquid dans un fichier markdown.
    
    Args:
        file_path (str): Chemin vers le fichier markdown à corriger
        backup (bool): Si True, crée une copie de sauvegarde du fichier original
        
    Returns:
        tuple: (success, message)
    """
    if not os.path.exists(file_path):
        return False, f"Le fichier {file_path} n'existe pas."
    
    # Créer une sauvegarde si demandé
    if backup:
        backup_path = f"{file_path}.bak"
        try:
            with open(file_path, 'r', encoding='utf-8') as src, open(backup_path, 'w', encoding='utf-8') as dst:
                dst.write(src.read())
            print(f"Sauvegarde créée: {backup_path}")
        except Exception as e:
            return False, f"Erreur lors de la création de la sauvegarde: {str(e)}"
    
    try:
        # Lire le contenu du fichier
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            lines = content.split('\n')
            
        # Variables pour le suivi
        fixed_count = 0
        in_code_block = False
        code_block_start = 0
        blocks_to_wrap = []
        
        # Première passe: identifier les blocs de code contenant des doubles accolades
        for i, line in enumerate(lines):
            # Vérifier si nous entrons ou sortons d'un bloc de code
            if line.strip().startswith('```'):
                if in_code_block:
                    # Nous sortons d'un bloc de code
                    in_code_block = False
                    if any('{{' in lines[j] for j in range(code_block_start + 1, i)):
                        blocks_to_wrap.append((code_block_start, i))
                else:
                    # Nous entrons dans un bloc de code
                    in_code_block = True
                    code_block_start = i
            
            # Si nous ne sommes pas dans un bloc de code, chercher des doubles accolades isolées
            elif not in_code_block and '{{' in line and '}}' in line and '{% raw %}' not in line and '{% endraw %}' not in line:
                # Ligne isolée avec des doubles accolades
                lines[i] = '{% raw %}' + line + '{% endraw %}'
                fixed_count += 1
        
        # Deuxième passe: envelopper les blocs de code identifiés avec raw tags
        for start, end in blocks_to_wrap:
            lines[start] = '{% raw %}' + lines[start]
            lines[end] = lines[end] + '{% endraw %}'
            fixed_count += 1
        
        # Appliquer une fixation additionnelle pour le problème spécifique de {{A..Z}
        content = '\n'.join(lines)
        pattern = r'(for\s+\w+\s+in\s+\{\{[A-Za-z0-9.,\s]+\}\})'
        if re.search(pattern, content) and '{% raw %}' not in content:
            content = re.sub(pattern, r'{% raw %}\1{% endraw %}', content)
            fixed_count += re.search(pattern, content).group(0).count('{{')
        
        # Écrire le contenu modifié
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        
        return True, f"Correction terminée. {fixed_count} instances corrigées."
    
    except Exception as e:
        return False, f"Erreur lors de la correction du fichier: {str(e)}"

def fix_all_markdown_files(directory_path, backup=True):
    """
    Corrige tous les fichiers markdown dans un répertoire.
    
    Args:
        directory_path (str): Chemin vers le répertoire contenant les fichiers markdown
        backup (bool): Si True, crée une copie de sauvegarde des fichiers originaux
        
    Returns:
        tuple: (success, message)
    """
    if not os.path.isdir(directory_path):
        return False, f"Le répertoire {directory_path} n'existe pas."
    
    success_count = 0
    error_count = 0
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.md') or file.endswith('.markdown'):
                file_path = os.path.join(root, file)
                success, message = fix_liquid_syntax(file_path, backup)
                print(f"{file_path}: {message}")
                if success:
                    success_count += 1
                else:
                    error_count += 1
    
    return True, f"Correction terminée. {success_count} fichiers corrigés, {error_count} erreurs."

def main():
    parser = argparse.ArgumentParser(description='Corrige les erreurs de syntaxe Liquid dans les fichiers markdown Jekyll.')
    
    # Arguments obligatoires et optionnels
    parser.add_argument('path', help='Chemin vers le fichier ou le répertoire à traiter')
    parser.add_argument('--no-backup', action='store_true', help='Ne pas créer de backup des fichiers originaux')
    parser.add_argument('--recursive', action='store_true', help='Traiter récursivement tous les fichiers markdown dans le répertoire spécifié')
    
    args = parser.parse_args()
    
    backup = not args.no_backup
    
    if os.path.isdir(args.path) and args.recursive:
        success, message = fix_all_markdown_files(args.path, backup)
    elif os.path.isfile(args.path):
        success, message = fix_liquid_syntax(args.path, backup)
    else:
        if os.path.isdir(args.path) and not args.recursive:
            print("Le chemin spécifié est un répertoire. Utilisez --recursive pour traiter tous les fichiers du répertoire.")
            return 1
        else:
            print(f"Le chemin spécifié '{args.path}' n'existe pas.")
            return 1
    
    print(message)
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
