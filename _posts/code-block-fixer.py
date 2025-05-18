#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Correcteur de blocs de code - Solution radicale
-----------------------------------------------

Ce script corrige spécifiquement le format des blocs de code qui montrent
le mot "shell" après la commande, comme dans l'image fournie.
"""

import re
import sys
import os


def fix_code_blocks(markdown_content):
    """
    Corrige radicalement les blocs de code pour qu'ils soient propres et conformes.
    """
    # Étape 1: Nettoyer le format des commandes avec le mot "shell" à la fin
    pattern_bad_code = r'(bash\s+`([^`]+)`\s+shell)'
    
    def clean_command(match):
        command = match.group(2).strip()
        return f"```\n{command}\n```"
    
    # Remplacer tous les motifs problématiques
    content = re.sub(pattern_bad_code, clean_command, markdown_content)
    
    # Étape 2: Réparer les autres blocs de code mal formatés
    # Remplacer les blocs avec `commande` shell
    content = re.sub(r'`([^`\n]+)`\s+shell', r'```\n\1\n```', content)
    
    # Étape 3: Corriger les titres des sections pour qu'ils soient plus concis
    # Remplacer "Affiche tous les X dans le Framework" par "Affiche tous les X"
    content = re.sub(r'(Affiche tous les [^d]+) dans le Framework', r'\1', content)
    
    # Regrouper les commandes similaires sous des titres de section
    if "Metasploit" in content:
        # Ajouter un titre de section regroupant les commandes Metasploit si absent
        if not re.search(r'#+\s+Commandes Metasploit', content):
            content = re.sub(r'Metasploit\s+🎯\s+🎯', r'## Commandes Metasploit 🎯', content)
    
    # Étape 4: Format ultra-compact pour les titres
    # Utiliser des titres H3 pour chaque commande
    content = re.sub(r'^([A-Z][^#\n].+)$', r'### \1', content, flags=re.MULTILINE)
    
    # Étape 5: Nettoyer les espaces superflus
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    return content


def process_file(input_file, output_file=None):
    """
    Traite un fichier Markdown pour corriger les blocs de code.
    """
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        transformed_content = fix_code_blocks(content)
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(transformed_content)
            print(f"Correction terminée ! Fichier sauvegardé : {output_file}")
        
        return transformed_content
        
    except Exception as e:
        print(f"Erreur lors du traitement du fichier : {e}")
        return None


def main():
    """Point d'entrée principal du script"""
    if len(sys.argv) >= 2:
        # Mode ligne de commande
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) >= 3 else None
        
        if not output_file:
            # Générer un nom de fichier de sortie par défaut
            base, ext = os.path.splitext(input_file)
            output_file = f"{base}_corrected{ext}"
        
        process_file(input_file, output_file)
    else:
        # Mode interactif
        print("=== Correcteur de Blocs de Code - Solution Radicale ===")
        input_file = input("Chemin du fichier Markdown à corriger: ")
        
        if not os.path.isfile(input_file):
            print(f"Erreur : Le fichier '{input_file}' n'existe pas.")
            return
        
        output_prompt = "Chemin du fichier de sortie (Entrée pour générer automatiquement): "
        output_file = input(output_prompt)
        
        if not output_file:
            base, ext = os.path.splitext(input_file)
            output_file = f"{base}_corrected{ext}"
        
        result = process_file(input_file, output_file)
        if result:
            print(f"\nAperçu du résultat :\n")
            print("-" * 60)
            print(result[:500] + "..." if len(result) > 500 else result)
            print("-" * 60)


if __name__ == "__main__":
    main()
