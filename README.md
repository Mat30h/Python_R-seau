# 🌐 Network Scanner Pro

**Outil professionnel d'analyse réseau** - Scanner IP avancé avec détection de services et analyse de sécurité.

## 📋 Description

Network Scanner Pro est un scanner réseau complet développé en Python qui permet de :
- 🔍 Scanner des réseaux entiers (notation CIDR)
- 🎯 Détecter les hôtes actifs et services ouverts
- 🔐 Identifier les vulnérabilités de sécurité
- 📊 Générer des rapports détaillés (CSV, JSON, HTML)
- 💾 Historiser les scans dans une base SQLite
- ⚡ Scanner en parallèle pour des performances optimales

## 🚀 Installation Rapide

### Prérequis
- Python 3.7 ou supérieur
- Système : Windows, Linux, macOS

### Installation des dépendances

```bash
pip install -r requirements.txt
```

**Dépendances optionnelles pour fonctionnalités avancées :**
```bash
pip install psutil ping3 pyyaml scapy
```

## 💻 Utilisation

### Scan Rapide

```bash
python network_scanner_pro.py
```

Le scanner détectera automatiquement votre interface réseau et vous proposera un scan interactif.

### Modes de Scan

Le scanner propose 4 profils prédéfinis :

| Profil | Ports | Threads | Durée estimée | Usage |
|--------|-------|---------|---------------|-------|
| **Quick** | 3 ports | 50 | ~30s | Test rapide |
| **Standard** | 14 ports | 100 | ~2min | Usage quotidien |
| **Full** | 1024 ports | 200 | ~15min | Scan complet |
| **Security** | 18 ports | 150 | ~3min | Audit sécurité |

### Exemples d'Utilisation

**Scan standard avec export JSON :**
```bash
python network_scanner_pro.py --network 192.168.1.0/24 --profile standard --export json
```

**Scan de sécurité avec tous les exports :**
```bash
python network_scanner_pro.py --network 10.0.0.0/24 --profile security --export csv,json,html
```

**Scan personnalisé :**
```bash
python network_scanner_pro.py --network 172.16.0.0/16 --ports 22,80,443,8080 --threads 200
```

## 📊 Formats d'Export

### CSV
Tableau structuré avec toutes les informations : IP, hostname, ports ouverts, services, OS.

### JSON
Format structuré pour intégration avec d'autres outils :
```json
{
  "ip": "192.168.1.100",
  "hostname": "server01",
  "open_ports": [[22, true, "SSH-2.0-OpenSSH_8.2"]],
  "os_info": "Linux",
  "vulnerabilities": []
}
```

### HTML
Rapport visuel interactif avec :
- Statistiques du scan
- Tableau interactif filtrable
- Code couleur pour les vulnérabilités
- Graphiques de répartition

## 🔧 Utilitaires

Le fichier `scanner_utils.py` fournit des outils de maintenance :

```bash
# Statistiques des scans
python scanner_utils.py stats

# Nettoyage de la base de données
python scanner_utils.py cleanup --days 30

# Comparaison de deux scans
python scanner_utils.py compare scan1.json scan2.json

# Santé de la base de données
python scanner_utils.py health
```

## 🛡️ Détection de Sécurité

Le scanner identifie automatiquement :

| Port | Service | Niveau de risque |
|------|---------|------------------|
| 21 | FTP | 🔴 Critique |
| 23 | Telnet | 🔴 Critique |
| 135, 139, 445 | SMB/NetBIOS | 🔴 Critique |
| 3389 | RDP | 🟡 Moyen |
| 3306 | MySQL | 🟡 Moyen |
| 5432 | PostgreSQL | 🟡 Moyen |
| 27017 | MongoDB | 🟡 Moyen |

## 📁 Structure des Fichiers

```
analyzer_ip/
├── network_scanner_pro.py    # Scanner principal
├── scanner_utils.py          # Utilitaires de maintenance
├── requirements.txt          # Dépendances Python
├── config_example.yaml       # Exemple de configuration
├── README.md                 # Ce fichier
├── QUICKSTART.md            # Guide de démarrage rapide
├── CHANGELOG.md             # Historique des versions
└── scan_history.db          # Base de données des scans (auto-créée)
```

## ⚙️ Configuration Avancée

Créez un fichier `config.yaml` basé sur `config_example.yaml` :

```yaml
scan_profiles:
  custom:
    ports: [22, 80, 443, 3306, 5432]
    threads: 150
    timeout: 2

database:
  path: "scan_history.db"
  retention_days: 90
```

## 🎯 Cas d'Usage

### 1. Audit Réseau d'Entreprise
```bash
python network_scanner_pro.py --network 10.0.0.0/8 --profile security --export html
```

### 2. Monitoring Régulier
```bash
# À planifier dans cron/Task Scheduler
python network_scanner_pro.py --network 192.168.1.0/24 --profile quick
```

### 3. Analyse Comparative
```bash
# Premier scan
python network_scanner_pro.py --network 192.168.1.0/24 --export json

# Après modifications réseau
python network_scanner_pro.py --network 192.168.1.0/24 --export json

# Comparaison
python scanner_utils.py compare scan1.json scan2.json
```

## 📈 Performances

- **Quick scan** (3 ports, 254 IPs) : ~30 secondes
- **Standard scan** (14 ports, 254 IPs) : ~2 minutes
- **Full scan** (1024 ports, 254 IPs) : ~15 minutes
- **Security scan** (18 ports, 254 IPs) : ~3 minutes

*Performances testées sur réseau local avec latence < 5ms*

## ⚠️ Avertissement Légal

**IMPORTANT :** Cet outil doit être utilisé UNIQUEMENT sur :
- Vos propres réseaux
- Réseaux pour lesquels vous avez une autorisation écrite explicite

L'utilisation non autorisée de scanners réseau peut être **illégale** et constituer une violation de la loi sur la cybersécurité.

## 🔐 Sécurité

### Bonnes Pratiques
1. Ne scannez jamais sans autorisation
2. Limitez les scans aux heures creuses
3. Documentez tous les scans effectués
4. Protégez les résultats de scan (données sensibles)
5. Changez immédiatement les identifiants par défaut détectés

## 🐛 Dépannage

### Erreur "Permission denied"
- **Windows :** Exécutez en tant qu'administrateur
- **Linux/Mac :** Utilisez `sudo` pour les scans réseau

### "No module named 'psutil'"
```bash
pip install psutil
```

### Scan très lent
- Réduisez le nombre de threads
- Utilisez le profil "quick"
- Vérifiez votre connexion réseau

### Aucun hôte détecté
- Vérifiez que vous êtes sur le bon réseau
- Désactivez temporairement le pare-feu
- Essayez un autre profil de scan

## 📞 Support

Pour toute question ou bug :
1. Vérifiez la documentation (README.md, QUICKSTART.md)
2. Consultez les logs (`network_scanner.log`)
3. Vérifiez les issues existantes

## 📝 Licence

Ce projet est fourni à des fins éducatives et professionnelles.
Utilisez-le de manière responsable et légale.

## 🔄 Mises à Jour

Consultez `CHANGELOG.md` pour l'historique des versions et des fonctionnalités.

---

**Version actuelle :** 2.0.0  
**Dernière mise à jour :** Octobre 2025  
**Python requis :** 3.7+

---

Made with ❤️ for network administrators and security professionals
# Python_R-seau
