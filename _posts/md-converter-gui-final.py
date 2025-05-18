#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interface graphique pour optimiseur de notes de cybersécurité
------------------------------------------------------------

Interface utilisateur pour transformer vos notes en un format optimisé
pour les examens de cybersécurité, suivant exactement le style de
avhiram.github.io/posts/cpts/
"""

import os
import re
import sys
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, messagebox
import subprocess
import webbrowser

# Fonction principale de conversion - copie locale pour l'interface autonome
def optimize_cyber_notes(markdown_content):
    """
    Convertit tout le contenu en format optimisé pour les examens.
    
    Args:
        markdown_content (str): Le contenu Markdown à transformer
        
    Returns:
        str: Le contenu Markdown transformé
    """
    # Étape 1 : Convertir les tableaux en blocs plus propres
    content = convert_tables_to_clean_format(markdown_content)
    
    # Étape 2 : Remplacer les blocs de code shell par un format plus propre
    content = convert_shell_blocks(content)
    
    # Étape 3 : Améliorer la structure des sections
    content = improve_section_structure(content)
    
    # Étape 4 : Nettoyer et finaliser
    content = clean_and_finalize(content)
    
    return content


def convert_tables_to_clean_format(markdown_content):
    """
    Convertit les tableaux Markdown en format optimisé.
    """
    # Modèle regex pour détecter les tableaux Markdown
    table_pattern = r'(\|[^\n]+\|\n)((?:\|[\s]*:?[-]+:?[\s]*)+\|)(\n(?:\|[^\n]+\|\n?)+)'
    
    def table_replacer(match):
        header_row, separator, body_rows = match.groups()
        
        # Analyser l'en-tête
        headers = [cell.strip() for cell in header_row.split('|') if cell.strip()]
        
        # Trouver les colonnes importantes
        command_col_index = -1
        desc_col_index = -1
        
        for i, header in enumerate(headers):
            header_lower = header.lower()
            if any(term in header_lower for term in ['command', 'commande', 'cmd']):
                command_col_index = i
            elif any(term in header_lower for term in ['desc', 'description', 'explication', 'usage']):
                desc_col_index = i
        
        # Si on ne trouve pas de colonne de commande, laisser le tableau inchangé
        if command_col_index == -1:
            return match.group(0)
        
        # Analyser les lignes du corps
        result = []
        rows = body_rows.strip().split('\n')
        
        for row in rows:
            # Extraire les cellules
            cells = [cell.strip() for cell in row.split('|')[1:-1]]
            
            # S'assurer que nous avons assez de cellules
            if len(cells) <= max(command_col_index, desc_col_index if desc_col_index != -1 else 0):
                continue
                
            # Ignorer les lignes vides ou sans commande
            if not cells[command_col_index]:
                continue
            
            # Nettoyer la commande (enlever TOUTES les backquotes)
            command = cells[command_col_index]
            command = command.replace('`', '')  # Supprimer TOUTES les backquotes
            
            # Titre pour la commande
            if desc_col_index != -1 and cells[desc_col_index]:
                result.append(f"{cells[desc_col_index]}")
            
            # Ajouter autres informations importantes si disponibles
            extra_info = []
            for i, cell in enumerate(cells):
                if (i != command_col_index and 
                    i != desc_col_index and 
                    i < len(headers) and 
                    cell):
                    extra_info.append(f"{headers[i]}: {cell}")
            
            # Ajouter le bloc de code shell dans le style du site
            result.append("```shell")
            result.append(command)
            result.append("```")
            
            # Ajouter les infos supplémentaires après le bloc si nécessaire
            if extra_info:
                result.append("*" + " | ".join(extra_info) + "*")
            
            # Ajouter un séparateur pour une meilleure lisibilité
            result.append("")
        
        return "\n".join(result)
    
    # Remplacer tous les tableaux dans le contenu Markdown
    return re.sub(table_pattern, table_replacer, markdown_content, flags=re.DOTALL)


def convert_shell_blocks(content):
    """
    Convertit les blocs de code shell existants en format optimisé.
    """
    # Motif pour détecter les blocs de code shell
    shell_block_pattern = r'```(?:bash|shell)?\n(.*?)```'
    
    def shell_block_replacer(match):
        code = match.group(1).strip()
        
        # Nettoyer le code (supprimer les backticks initiaux si présents)
        if code.startswith('`') and code.endswith('`'):
            code = code[1:-1]
        else:
            code = code.replace('`', '')
        
        # Si le code ne contient pas de caractères shell spéciaux
        # et n'a pas d'explication au-dessus, c'est probablement juste une commande
        if not re.search(r'[<>|&;]', code) and not re.search(r'\n', code):
            return f"```shell\n{code}\n```"
        else:
            return f"```shell\n{code}\n```"
    
    # Remplacer tous les blocs de code shell
    return re.sub(shell_block_pattern, shell_block_replacer, content, flags=re.DOTALL)


def improve_section_structure(content):
    """
    Améliore la structure des sections pour faciliter la navigation.
    """
    # Modèle pour ajouter des icônes aux outils spécifiques
    tool_patterns = [
        (r'(#+\s*Rubeus\b)', r'\1 🔑'),
        (r'(#+\s*Mimikatz\b)', r'\1 🔓'),
        (r'(#+\s*Impacket\b)', r'\1 🛠️'),
        (r'(#+\s*PowerView\b)', r'\1 🔍'),
        (r'(#+\s*BloodHound\b)', r'\1 🩸'),
        (r'(#+\s*Metasploit\b)', r'\1 🎯'),
    ]
    
    # Améliorer les titres des sections
    for pattern, replacement in tool_patterns:
        content = re.sub(pattern, replacement, content)
    
    # Ajouter des séparateurs clairs entre les grandes sections
    improved_content = []
    lines = content.split('\n')
    
    for i, line in enumerate(lines):
        improved_content.append(line)
        
        # Si la ligne est un titre de niveau 2, ajouter un séparateur horizontal après
        if re.match(r'^##\s+', line) and i < len(lines) - 1 and not lines[i+1].startswith('---'):
            improved_content.append("")
    
    return '\n'.join(improved_content)


def clean_and_finalize(content):
    """
    Nettoie et finalise le contenu.
    """
    # 1. Remplacer les blocs de backticks vides ou mal formés
    content = re.sub(r'```\s*```', '', content)
    
    # 2. Convertir les blocs contenant force brute, SID, etc. en notation spéciale
    content = re.sub(r'`(force brute[^`]*)`', r'<span class="highlight">\1</span>', content)
    content = re.sub(r'`(SID[^`]*)`', r'<span class="highlight">\1</span>', content)
    content = re.sub(r'`(variable[^`]*)`', r'<span class="highlight">\1</span>', content)
    
    # 3. Assurer la cohérence des blocs shell
    # Remplacer les blocs de code qui n'ont pas de spécification de langage
    content = re.sub(r'```\n', r'```shell\n', content)
    
    # 4. Nettoyer les espaces et lignes vides en trop
    content = re.sub(r'\n{3,}', '\n\n', content)
    
    return content


class CyberNotesOptimizerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Optimiseur de Notes Cybersécurité - Format Examen")
        self.root.geometry("1050x750")
        self.root.minsize(800, 600)
        
        # Variables
        self.input_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.input_content = ""
        self.output_content = ""
        
        # Options
        self.remove_backticks = tk.BooleanVar(value=True)
        self.add_icons = tk.BooleanVar(value=True)
        self.compact_format = tk.BooleanVar(value=True)
        
        # Création de l'interface
        self.create_widgets()
        self.style_widgets()
        
    def style_widgets(self):
        # Configurer le style
        style = ttk.Style()
        
        # Palette de couleurs adaptée à la cybersécurité
        style.configure("TFrame", background="#252B2E")
        style.configure("TLabel", background="#252B2E", foreground="#E0E0E0", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"), background="#252B2E", foreground="#4ECDC4")
        style.configure("Subheader.TLabel", font=("Segoe UI", 12), background="#252B2E", foreground="#F7FFF7")
        
        # Configurer le fond de la fenêtre principale
        self.root.configure(bg="#252B2E")
        
    def create_widgets(self):
        # Cadre principal
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # En-tête
        header_label = ttk.Label(
            main_frame, 
            text="Optimiseur de Notes Cybersécurité - Format Examen", 
            style="Header.TLabel"
        )
        header_label.pack(pady=(0, 15), anchor=tk.W)
        
        # Description
        desc_label = ttk.Label(
            main_frame,
            text="Transforme vos notes en format optimisé pour l'examen CPTS",
            style="Subheader.TLabel"
        )
        desc_label.pack(pady=(0, 15), anchor=tk.W)
        
        # Section du fichier d'entrée
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Fichier d'entrée :").pack(side=tk.LEFT)
        ttk.Entry(input_frame, textvariable=self.input_file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(input_frame, text="Parcourir...", command=self.browse_input_file).pack(side=tk.LEFT)
        
        # Section du fichier de sortie
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_frame, text="Fichier de sortie :").pack(side=tk.LEFT)
        ttk.Entry(output_frame, textvariable=self.output_file_path, width=60).pack(side=tk.LEFT, padx=5)
        ttk.Button(output_frame, text="Parcourir...", command=self.browse_output_file).pack(side=tk.LEFT)
        
        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Options d'optimisation")
        options_frame.pack(fill=tk.X, pady=10)
        
        ttk.Checkbutton(
            options_frame,
            text="Supprimer les backquotes des commandes",
            variable=self.remove_backticks
        ).pack(anchor=tk.W, padx=10, pady=3)
        
        ttk.Checkbutton(
            options_frame,
            text="Ajouter des icônes aux outils (🛠️ Impacket, 🔑 Rubeus, etc.)",
            variable=self.add_icons
        ).pack(anchor=tk.W, padx=10, pady=3)
        
        ttk.Checkbutton(
            options_frame,
            text="Utiliser un format compact (réduit la longueur totale)",
            variable=self.compact_format
        ).pack(anchor=tk.W, padx=10, pady=3)
        
        # Boutons d'action
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        optimize_button = ttk.Button(
            action_frame, 
            text="Optimiser", 
            command=self.optimize_file
        )
        optimize_button.pack(side=tk.LEFT, padx=5)
        
        preview_button = ttk.Button(
            action_frame, 
            text="Prévisualiser", 
            command=self.preview_conversion
        )
        preview_button.pack(side=tk.LEFT, padx=5)
        
        # Conteneur pour l'aperçu
        preview_frame = ttk.LabelFrame(main_frame, text="Aperçu de l'optimisation")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Créer un panneau divisé pour afficher avant/après
        paned_window = ttk.PanedWindow(preview_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Panneau gauche (avant)
        left_frame = ttk.LabelFrame(paned_window, text="Notes originales")
        self.input_preview = scrolledtext.ScrolledText(
            left_frame, 
            wrap=tk.WORD, 
            width=45, 
            height=20,
            bg="#2D2D2D",
            fg="#E0E0E0",
            insertbackground="#FFFFFF"
        )
        self.input_preview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        paned_window.add(left_frame, weight=1)
        
        # Panneau droit (après)
        right_frame = ttk.LabelFrame(paned_window, text="Notes optimisées pour l'examen")
        self.output_preview = scrolledtext.ScrolledText(
            right_frame, 
            wrap=tk.WORD, 
            width=45, 
            height=20,
            bg="#2D2D2D",
            fg="#E0E0E0",
            insertbackground="#FFFFFF"
        )
        self.output_preview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        paned_window.add(right_frame, weight=1)
        
        # Barre d'état
        self.status_var = tk.StringVar()
        self.status_var.set("Prêt à optimiser vos notes pour l'examen CPTS")
        status_bar = ttk.Label(
            main_frame, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            padding=(5, 2)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def browse_input_file(self):
        """Ouvre une boîte de dialogue pour sélectionner le fichier d'entrée"""
        filetypes = [("Fichiers Markdown", "*.md"), ("Tous les fichiers", "*.*")]
        filename = filedialog.askopenfilename(
            title="Sélectionner vos notes en Markdown",
            filetypes=filetypes
        )
        
        if filename:
            self.input_file_path.set(filename)
            self.status_var.set(f"Fichier sélectionné : {os.path.basename(filename)}")
            
            # Mise à jour automatique du fichier de sortie
            if not self.output_file_path.get():
                base, ext = os.path.splitext(filename)
                self.output_file_path.set(f"{base}_exam_ready{ext}")
            
            # Charger le contenu pour l'aperçu
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    self.input_content = f.read()
                self.input_preview.delete(1.0, tk.END)
                self.input_preview.insert(tk.END, self.input_content)
            except Exception as e:
                self.status_var.set(f"Erreur lors de la lecture du fichier : {e}")
    
    def browse_output_file(self):
        """Ouvre une boîte de dialogue pour sélectionner le fichier de sortie"""
        filetypes = [("Fichiers Markdown", "*.md"), ("Tous les fichiers", "*.*")]
        filename = filedialog.asksaveasfilename(
            title="Enregistrer les notes optimisées",
            filetypes=filetypes,
            defaultextension=".md"
        )
        
        if filename:
            self.output_file_path.set(filename)
    
    def preview_conversion(self):
        """Prévisualise l'optimisation sans écrire de fichier"""
        if not self.input_content:
            if self.input_file_path.get():
                try:
                    with open(self.input_file_path.get(), 'r', encoding='utf-8') as f:
                        self.input_content = f.read()
                    self.input_preview.delete(1.0, tk.END)
                    self.input_preview.insert(tk.END, self.input_content)
                except Exception as e:
                    self.status_var.set(f"Erreur lors de la lecture du fichier : {e}")
                    return
            else:
                messagebox.showwarning("Fichier manquant", "Veuillez sélectionner un fichier de notes à optimiser.")
                return
        
        # Optimiser le contenu
        try:
            self.output_content = optimize_cyber_notes(self.input_content)
            
            # Appliquer les options
            if not self.add_icons.get():
                # Supprimer les émojis ajoutés
                self.output_content = re.sub(r'(#+\s*\w+\b)\s+[🔑🔓🛠️🔍🩸🎯]', r'\1', self.output_content)
                
            # Afficher le résultat
            self.output_preview.delete(1.0, tk.END)
            self.output_preview.insert(tk.END, self.output_content)
            
            # Calculer les statistiques
            input_lines = len(self.input_content.split('\n'))
            output_lines = len(self.output_content.split('\n'))
            reduction = 100 - (output_lines / input_lines * 100) if input_lines > 0 else 0
            
            # Mettre à jour le statut
            self.status_var.set(f"Prévisualisation générée - Réduction : {reduction:.1f}% ({input_lines} → {output_lines} lignes)")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'optimisation : {e}")
    
    def optimize_file(self):
        """Optimise le fichier et enregistre le résultat"""
        if not self.input_file_path.get():
            messagebox.showwarning("Fichier manquant", "Veuillez sélectionner un fichier de notes à optimiser.")
            return
        
        if not self.output_file_path.get():
            messagebox.showwarning("Fichier manquant", "Veuillez spécifier un fichier de sortie.")
            return
        
        try:
            # Prévisualiser d'abord pour être sûr
            self.preview_conversion()
            
            # Enregistrer le résultat
            with open(self.output_file_path.get(), 'w', encoding='utf-8') as f:
                f.write(self.output_content)
            
            # Mettre à jour le statut
            messagebox.showinfo(
                "Succès", 
                f"Notes optimisées et enregistrées avec succès !\n\n"
                f"Fichier : {os.path.basename(self.output_file_path.get())}"
            )
            
            # Propose d'ouvrir le fichier
            if messagebox.askyesno("Ouvrir le fichier", "Souhaitez-vous ouvrir le fichier optimisé ?"):
                try:
                    # Ouvrir avec l'application par défaut
                    if sys.platform.startswith('darwin'):  # macOS
                        subprocess.call(('open', self.output_file_path.get()))
                    elif os.name == 'nt':  # Windows
                        os.startfile(self.output_file_path.get())
                    elif os.name == 'posix':  # Linux
                        subprocess.call(('xdg-open', self.output_file_path.get()))
                except Exception:
                    messagebox.showinfo(
                        "Information", 
                        "Impossible d'ouvrir automatiquement le fichier. Vous pouvez l'ouvrir manuellement."
                    )
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur s'est produite lors de l'optimisation : {e}")
            self.status_var.set(f"Erreur : {e}")


def main():
    """Point d'entrée principal de l'application"""
    root = tk.Tk()
    app = CyberNotesOptimizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
