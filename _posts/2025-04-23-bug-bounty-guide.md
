---
layout: post
title: "Bug Bounty Guide"
date: 2025-04-23
author: Liham
image: /images/bugbounty.jpg
---


# Guide Complet de Bug Bounty

...



## Table des Matières
- [Énumération de Sous-domaines](#énumération-de-sous-domaines)
- [Collecte d'URLs](#collecte-durls)
- [Découverte de Données Sensibles](#découverte-de-données-sensibles)
- [Test XSS](#test-xss)
- [Test LFI](#test-lfi)
- [Test CORS](#test-cors)
- [Scan WordPress](#scan-wordpress)
- [Extensions de Navigateur](#extensions-de-navigateur)
- [Scan Réseau](#scan-réseau)
- [Découverte de Paramètres](#découverte-de-paramètres)
- [Analyse JavaScript](#analyse-javascript)
- [Filtrage par Type de Contenu](#filtrage-par-type-de-contenu)
- [Dorks Shodan](#dorks-shodan)
- [Méthode FFUF avec Fichier de Requête](#méthode-ffuf-avec-fichier-de-requête)
- [Techniques Avancées](#techniques-avancées)

## Énumération de Sous-domaines

### Découverte Basique de Sous-domaines
Découvre les sous-domaines en utilisant subfinder avec énumération récursive et sauvegarde les résultats dans un fichier.

```bash
subfinder -d example.com -all -recursive > subexample.com.txt
```

### Filtrage des Sous-domaines Actifs
Filtre les sous-domaines découverts en utilisant httpx et sauvegarde ceux qui sont actifs dans un fichier.

```bash
cat subexample.com.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subexample.coms_alive.txt
```

### Vérification de Prise de Contrôle de Sous-domaine
Vérifie les vulnérabilités de prise de contrôle de sous-domaine en utilisant subzy.

```bash
subzy run --targets subexample.coms.txt --concurrency 100 --hide_fails --verify_ssl
```

## Collecte d'URLs

### Collecte Passive d'URLs
Collecte les URLs de diverses sources et les sauvegarde dans un fichier.

```bash
katana -u subexample.coms_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt
```

### Récupération Avancée d'URLs
Collecte les URLs de diverses sources et les sauvegarde dans un fichier.

```bash
echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txt
katana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txt
cat output.txt | sed 's/=.*/=/' >final.txt
```

### Collecte d'URLs avec GAU
Collecte les URLs en utilisant GAU et les sauvegarde dans un fichier.

```bash
echo example.com | gau --mc 200 | urldedupe >urls.txt
cat urls.txt | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep '=' | sort > output.txt
cat output.txt | sed 's/=.*/=/' >final.txt
```

## Découverte de Données Sensibles

### Détection de Fichiers Sensibles
Détecte les fichiers sensibles sur le serveur web.

```bash
cat allurls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"
```

### Dork pour la Divulgation d'Informations
Recherche les vulnérabilités de divulgation d'informations en utilisant un dork.

```bash
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```

### Détection de Dépôt Git
Détecte les dépôts Git sur le serveur web.

```bash
cat example.coms.txt | grep "SUCCESS" | gf urls | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe
```

### Scanner de Divulgation d'Informations
Vérifie les vulnérabilités de divulgation d'informations en utilisant un scanner.

```bash
echo https://example.com | gau | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"
```

### Recherche de Buckets AWS S3
Recherche les buckets AWS S3 associés à la cible.

```bash
s3scanner scan -d example.com
```

### Recherche de Clés API
Recherche les clés API et les tokens exposés dans les fichiers JavaScript.

```bash
cat allurls.txt | grep -E "\.js$" | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 | xargs -I% curl -s % | grep -E "(API_KEY|api_key|apikey|secret|token|password)"
```

## Test XSS

### Pipeline de Chasse au XSS
Collecte les vulnérabilités XSS en utilisant divers outils et les sauvegarde dans un fichier.

```bash
echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt
```

### XSS avec Dalfox
Utilise Dalfox pour scanner les vulnérabilités XSS.

```bash
cat xss_params.txt | dalfox pipe --blind https://your-collaborator-url --waf-bypass --silence
```

### Recherche de XSS Stockés
Trouve les vulnérabilités XSS stockées potentielles en scannant les formulaires.

```bash
cat urls.txt | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high
```

### Détection de XSS DOM
Détecte les vulnérabilités XSS basées sur le DOM potentielles.

```bash
cat js_files.txt | Gxss -c 100 | sort -u | dalfox pipe -o dom_xss_results.txt
```

## Test LFI

### Méthodologie LFI
Teste les vulnérabilités d'inclusion de fichiers locaux (LFI) en utilisant diverses méthodes.

```bash
echo "https://example.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:(x|\*|\$[^\:]*):0:0:" -v
```

## Test CORS

### Vérification CORS Basique
Vérifie la politique de partage des ressources cross-origin (CORS) d'un site web.

```bash
curl -H "Origin: http://example.com" -I https://example.com/wp-json/
```

### CORScanner
Scanner rapide de mauvaises configurations CORS qui aide à identifier les vulnérabilités CORS potentielles.

```bash
python3 CORScanner.py -u https://example.com -d -t 10
```

### Scan CORS avec Nuclei
Utilise Nuclei pour scanner les mauvaises configurations CORS sur plusieurs domaines.

```bash
cat example.coms.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt
```

### Test de Réflexion d'Origine CORS
Teste la vulnérabilité de réflexion d'origine dans la configuration CORS.

```bash
curl -H "Origin: https://evil.com" -I https://example.com/api/data | grep -i "access-control-allow-origin: https://evil.com"
```

## Scan WordPress

### Scan WordPress Agressif
Scanne un site WordPress pour les vulnérabilités et sauvegarde les résultats dans un fichier.

```bash
wpscan --url https://example.com --disable-tls-checks --api-token YOUR_TOKEN -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force
```

## Extensions de Navigateur

Liste d'extensions utiles pour le bug bounty:

| Extension | Description | Lien |
|-----------|-------------|------|
| Greb | Capture et manipule facilement les paramètres de formulaire, les paramètres d'URL et les données de formulaire | [Github](https://github.com/greb-hunter/greb) |
| TruffleHog | Trouve des clés API cachées et des secrets dans les sites web | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/trufflehog/) |
| FoxyProxy | Gestion essentielle de proxy pour Burp Suite et autres applications MITM | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/foxyproxy-standard/) |
| Wappalyzer | Identifie les technologies, CMS et frameworks utilisés par les sites web | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/wappalyzer/) |
| Temp Mail | Accès rapide aux services d'email temporaires | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/temp-mail/) |
| Hunter.io | Extrait toutes les adresses email des sites web, utile pour la soumission de rapports | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/hunterio/) |
| HackTools | Collection de payloads et d'outils utiles pour les tests de pénétration | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/hacktools/) |
| Cookie Editor | Gestion avancée des cookies avec détection de flag de sécurité | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/cookie-editor/) |
| WebRTC Disable | Protège l'IP VPN des fuites WebRTC | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/disable-webrtc/) |
| Link Gopher | Extrait tous les domaines et liens des sites web et des résultats Google | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/link-gopher/) |
| FindSomething | Découvre les paramètres cachés et les clés secrètes | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/findsomething/) |
| DotGit | Trouve les dépôts .git exposés pour une potentielle divulgation d'informations P1 | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/dotgit/) |
| Open Multiple URLs | Ouvre plusieurs sites simultanément | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/open-multiple-urls/) |
| uBlock Origin | Bloque les publicités et les trackers pour des tests plus propres | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/ublock-origin/) |
| Dark Reader | Mode sombre pour une meilleure chasse nocturne | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/darkreader/) |
| User-Agent Switcher | Teste les sites avec différentes chaînes d'user-agent | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/user-agent-switcher-revived/) |
| Retire.js | Identifie les bibliothèques JavaScript vulnérables | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/retire-js/) |
| Page Translator | Traduit les sites web dans votre langue préférée | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/traduzir-paginas-web/) |
| WaybackURLs | Récupère les URLs depuis l'archive Wayback Machine | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/waybackurls/) |
| Shodan | Visualise les détails d'hébergement, la propriété IP et les services ouverts pour les sites web | [Firefox Store](https://addons.mozilla.org/fr/firefox/addon/shodan-addon/) |

## Scan Réseau

### Scan Naabu
Scanne les ports ouverts et les services en utilisant Naabu.

```bash
naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt
```

### Scan Complet Nmap
Effectue un scan de port complet en utilisant Nmap.

```bash
nmap -p- --min-rate 1000 -T4 -A example.com -oA fullscan
```

### Masscan
Scanne les ports ouverts et les services en utilisant Masscan.

```bash
masscan -p0-65535 example.com --rate 100000 -oG masscan-results.txt
```

## Découverte de Paramètres

### Arjun Passif
Découvre passivement les paramètres en utilisant Arjun.

```bash
arjun -u https://example.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"
```

### Arjun avec Wordlist
Utilise Arjun pour découvrir les paramètres en utilisant une wordlist personnalisée.

```bash
arjun -u https://example.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"
```

## Analyse JavaScript

### Chasse aux Fichiers JS
Collecte les fichiers JavaScript d'un site web et les analyse.

```bash
echo example.com | katana -d 5 | grep -E "\.js$" | nuclei -t /path/to/nuclei-templates/http/exposures/ -c 30
```

### Analyse de Fichiers JS
Analyse les fichiers JavaScript collectés.

```bash
cat alljs.txt | nuclei -t /path/to/nuclei-templates/http/exposures/
```

## Filtrage par Type de Contenu

### Vérification de Type de Contenu
Vérifie le type de contenu des URLs.

```bash
echo example.com | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'
```

### Vérification de Contenu JavaScript
Vérifie le contenu JavaScript dans les URLs.

```bash
echo example.com | gau | grep '\.js-php-jsp-other extens$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'
```

## Dorks Shodan

### Recherche de Certificat SSL
Recherche les certificats SSL en utilisant Shodan.

```bash
Ssl.cert.subject.CN:"example.com" 200
```

## Méthode FFUF avec Fichier de Requête

### LFI avec Fichier de Requête
Utilise FFUF pour bruteforcer les vulnérabilités LFI en utilisant un fichier de requête.

```bash
ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr "root:"
```

### XSS avec Fichier de Requête
Utilise FFUF pour bruteforcer les vulnérabilités XSS en utilisant un fichier de requête.

```bash
ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr "<script>alert('XSS')</script>"
```

## Techniques Avancées

### Test d'En-tête XSS/SSRF
Teste les vulnérabilités XSS et SSRF en utilisant diverses méthodes.

```bash
cat example.coms.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotor'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotor'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotor'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e "\e[1;32m$url\e[0m""\n""Method[1] X-Forwarded-For: xss+ssrf => $xss1""\n""Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2""\n""Method[3] Host: xss+ssrf ==> $xss3""\n""Method[4] GET http://xss.yourburpcollabrotor HTTP/1.1 ""\n";done
```
