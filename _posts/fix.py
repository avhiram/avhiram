#!/usr/bin/env python3

import re
import sys
import os

def fix_liquid_syntax(file_path):
    # Lire le contenu du fichier
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Rechercher les blocs de code avec des doubles accolades
    # Cette regex cherche des blocs de code (délimités par ```) qui contiennent {{
    code_block_pattern = r'(```[^\n]*\n[\s\S]*?{{[\s\S]*?```)'
    
    # Fonction pour remplacer un bloc de code avec des balises raw
    def wrap_with_raw(match):
        block = match.group(1)
        # Vérifier si le bloc n'est pas déjà dans un {% raw %}
        if '{% raw %}' not in block:
            return '{% raw %}\n' + block + '\n{% endraw %}'
        return block
    
    # Appliquer le remplacement
    modified_content = re.sub(code_block_pattern, wrap_with_raw, content)
    
    # Chercher aussi les doubles accolades qui ne sont pas dans des blocs de code
    # mais qui sont dans des lignes isolées (comme les commandes bash)
    line_pattern = r'(^.*{{.*}}.*$)'
    
    # Traiter le contenu ligne par ligne
    lines = modified_content.split('\n')
    for i in range(len(lines)):
        line = lines[i]
        if '{{' in line and '}}' in line and '{% raw %}' not in line and '```' not in line:
            # Vérifier si cette ligne n'est pas déjà dans un bloc raw
            # et n'est pas une partie d'un bloc de code
            if (i == 0 or '{% endraw %}' in lines[i-1] or '```' not in lines[i-1]) and \
               (i == len(lines)-1 or '{% raw %}' in lines[i+1] or '```' not in lines[i+1]):
                lines[i] = '{% raw %}' + line + '{% endraw %}'
    
    modified_content = '\n'.join(lines)
    
    # Écrire le contenu modifié dans un nouveau fichier
    output_path = file_path + '.fixed'
    with open(output_path, 'w', encoding='utf-8') as file:
        file.write(modified_content)
    
    print(f"Fichier corrigé sauvegardé comme {output_path}")
    return output_path

def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_liquid_syntax.py <chemin_vers_fichier_markdown>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print(f"Erreur: Le fichier {file_path} n'existe pas.")
        sys.exit(1)
    
    fixed_file = fix_liquid_syntax(file_path)
    print(f"Terminé. Vérifiez {fixed_file} et remplacez l'original si tout semble correct.")

if __name__ == "__main__":
    main()
