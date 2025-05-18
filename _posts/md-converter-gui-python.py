#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Convertisseur GUI de tableaux Markdown en blocs de code bash
------------------------------------------------------------

Interface graphique pour transformer les tableaux de commandes Markdown
en blocs de code bash individuels avec une explication pour chaque commande.
"""

import os
import re
import sys
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, messagebox

# Fonction principale de conversion (identique à celle du script en ligne de commande)
def convert_tables_to_code_blocks(markdown_content):
    """
    Convertit les tableaux Markdown en blocs de code bash avec explications.
    
    Args:
        markdown_content (str): Le contenu Markdown à transformer
        
    Returns:
        str: Le contenu Markdown transformé
    """
    
    # Modèle regex pour détecter les tableaux Markdown
    # Capture: En-tête, séparateur, et corps du tableau
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
                
            # Ajouter la description comme titre si elle existe
            if desc_col_index != -1 and cells[desc_col_index]:
                result.append(f"### {cells[desc_col_index]}\n")
            
            # Ajouter d'autres informations si disponibles
            for i, cell in enumerate(cells):
                if (i != command_col_index and 
                    i != desc_col_index and 
                    i < len(headers) and 
                    cell):
                    result.append(f"**{headers[i]}**: {cell}\n")
            
            # Si nous avons ajouté des informations supplémentaires, ajouter un espace
            if any(i != command_col_index and i != desc_col_index and cells[i] 
                  for i in range(min(len(cells), len(headers)))):
                result.append("")
            
            # Ajouter le bloc de code
            result.append(f"```bash\n{cells[command_col_index]}\n```\n")
        
        return "\n".join(result)
    
    # Remplacer tous les tableaux dans le contenu Markdown
    transformed_content = re.sub(table_pattern, table_replacer, markdown_content, flags=re.DOTALL)
    return transformed_content


class MarkdownConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Convertisseur de Tableaux MD → Blocs de Code")
        self.root.geometry("900x700")
        self.root.minsize(700, 500)
        
        # Variables
        self.input_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()
        self.input_content = ""
        self.output_content = ""
        
        # Création de l'interface
        self.create_widgets()
        self.style_widgets()
        
    def style_widgets(self):
        # Appliquer des styles à l'interface
        style = ttk.Style()
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("TLabel", font=("Segoe UI", 10), background="#f0f0f0")
        style.configure("Header.TLabel", font=("Segoe UI", 12, "bold"), background="#f0f0f0")
        
    def create_widgets(self):
        # Cadre principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # En-tête
        header_label = ttk.Label(
            main_frame, 
            text="Convertir les tableaux Markdown en blocs de code bash", 
            style="Header.TLabel"
        )
        header_label.pack(pady=(0, 10), anchor=tk.W)
        
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
        
        # Boutons d'action
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(action_frame, text="Convertir", command=self.convert_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Prévisualiser", command=self.preview_conversion).pack(side=tk.LEFT, padx=5)
        
        # Conteneur pour l'aperçu
        preview_frame = ttk.LabelFrame(main_frame, text="Aperçu de la conversion")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Créer un panneau divisé pour afficher avant/après
        paned_window = ttk.PanedWindow(preview_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Panneau gauche (avant)
        left_frame = ttk.LabelFrame(paned_window, text="Contenu original")
        self.input_preview = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, width=40, height=20)
        self.input_preview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        paned_window.add(left_frame, weight=1)
        
        # Panneau droit (après)
        right_frame = ttk.LabelFrame(paned_window, text="Contenu converti")
        self.output_preview = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=40, height=20)
        self.output_preview.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        paned_window.add(right_frame, weight=1)
        
        # Barre d'état
        self.status_var = tk.StringVar()
        self.status_var.set("Prêt")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def browse_input_file(self):
        """Ouvre une boîte de dialogue pour sélectionner le fichier d'entrée"""
        filetypes = [("Fichiers Markdown", "*.md"), ("Tous les fichiers", "*.*")]
        filename = filedialog.askopenfilename(
            title="Sélectionner un fichier Markdown",
            filetypes=filetypes
        )
        
        if filename:
            self.input_file_path.set(filename)
            self.status_var.set(f"Fichier sélectionné : {os.path.basename(filename)}")
            
            # Mise à jour automatique du fichier de sortie
            if not self.output_file_path.get():
                base, ext = os.path.splitext(filename)
                self.output_file_path.set(f"{base}_converti{ext}")
            
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
            title="Enregistrer sous",
            filetypes=filetypes,
            defaultextension=".md"
        )
        
        if filename:
            self.output_file_path.set(filename)
    
    def preview_conversion(self):
        """Prévisualise la conversion sans écrire de fichier"""
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
                messagebox.showwarning("Fichier manquant", "Veuillez sélectionner un fichier d'entrée.")
                return
        
        # Convertir le contenu
        self.output_content = convert_tables_to_code_blocks(self.input_content)
        
        # Afficher le résultat
        self.output_preview.delete(1.0, tk.END)
        self.output_preview.insert(tk.END, self.output_content)
        
        # Mettre à jour le statut
        self.status_var.set("Prévisualisation générée")
    
    def convert_file(self):
        """Convertit le fichier et enregistre le résultat"""
        if not self.input_file_path.get():
            messagebox.showwarning("Fichier manquant", "Veuillez sélectionner un fichier d'entrée.")
            return
        
        if not self.output_file_path.get():
            messagebox.showwarning("Fichier manquant", "Veuillez spécifier un fichier de sortie.")
            return
        
        try:
            # Si le contenu n'est pas encore chargé, le charger
            if not self.input_content:
                with open(self.input_file_path.get(), 'r', encoding='utf-8') as f:
                    self.input_content = f.read()
                self.input_preview.delete(1.0, tk.END)
                self.input_preview.insert(tk.END, self.input_content)
            
            # Convertir et enregistrer
            self.output_content = convert_tables_to_code_blocks(self.input_content)
            
            with open(self.output_file_path.get(), 'w', encoding='utf-8') as f:
                f.write(self.output_content)
            
            # Afficher le résultat
            self.output_preview.delete(1.0, tk.END)
            self.output_preview.insert(tk.END, self.output_content)
            
            # Mettre à jour le statut
            messagebox.showinfo("Succès", f"Fichier converti et enregistré avec succès :\n{self.output_file_path.get()}")
            self.status_var.set(f"Conversion terminée : {os.path.basename(self.output_file_path.get())}")
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur s'est produite : {e}")
            self.status_var.set(f"Erreur : {e}")


def main():
    """Point d'entrée principal de l'application"""
    root = tk.Tk()
    app = MarkdownConverterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
