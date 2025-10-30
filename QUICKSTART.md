# 🚀 Guide de Démarrage Rapide

## Installation en 3 étapes

### 1. Installation des dépendances

```bash
pip install -r requirements.txt
```

### 2. Premier scan

```bash
# Le scanner va auto-détecter votre réseau
python network_scanner_pro.py
```

### 3. Consulter les résultats

Les résultats s'affichent dans la console et sont sauvegardés automatiquement.

---

## Scénarios Courants

### 🔍 Découvrir tous les équipements de mon réseau

```bash
python network_scanner_pro.py --profile standard --export-csv
```

**Résultat** : Fichier CSV avec tous les hôtes détectés

---

### 🛡️ Audit de sécurité

```bash
python network_scanner_pro.py --profile security --export-html
```

**Résultat** : Rapport HTML avec alertes de sécurité

---

### ⚡ Scan rapide (3 ports uniquement)

```bash
python network_scanner_pro.py --profile quick
```

**Résultat** : Scan en ~30 secondes pour un réseau /24

---

### 🎯 Scanner un réseau spécifique

```bash
python network_scanner_pro.py --cidr 192.168.1.0/24
```

---

### 📊 Voir l'historique

```bash
python network_scanner_pro.py --history
```

---

### 🔧 Scanner des ports spécifiques

```bash
python network_scanner_pro.py --ports 22,80,443,3389,8080
```

---

## Exemples de Commandes Avancées

### Scan complet d'un réseau d'entreprise

```bash
python network_scanner_pro.py \
  --cidr 10.0.0.0/24 \
  --profile full \
  --threads 200 \
  --export-all \
  -o ./rapports/audit_2025
```

### Scan avec timeout personnalisé (réseau lent)

```bash
python network_scanner_pro.py \
  --ping-timeout 2.0 \
  --conn-timeout 1.5 \
  --threads 50
```

### Scan silencieux (sans banner)

```bash
python network_scanner_pro.py --no-banner --profile quick
```

---

## Utilitaires de Maintenance

### Voir les statistiques de la base de données

```bash
python scanner_utils.py stats
```

### Nettoyer les vieux scans (>90 jours)

```bash
python scanner_utils.py cleanup --days 90
```

### Comparer deux scans

```bash
# 1. Voir l'historique pour obtenir les IDs
python network_scanner_pro.py --history

# 2. Comparer
python scanner_utils.py compare <scan_id1> <scan_id2>
```

### Rapport de santé d'un réseau

```bash
python scanner_utils.py health 192.168.1.0/24
```

### Analyse de tendances

```bash
python scanner_utils.py trending 192.168.1.0/24 --days 30
```

---

## Interprétation des Résultats

### Console Output

```
✓ 192.168.1.1   | RTT:2.5ms | Ports:[80,443] | router.local
```

- ✓ = Hôte accessible (répond au ping ou a des ports ouverts)
- RTT = Temps de réponse en millisecondes
- Ports = Liste des ports TCP ouverts
- Dernière colonne = Nom d'hôte (DNS inversé)

### Statuts

- **UP** : Hôte répond au ping
- **DOWN** : Hôte ne répond pas (peut avoir un firewall qui bloque ICMP)
- **Ports ouverts** : Service accessible sur le port indiqué

### Alertes de Sécurité

```
⚠️ SECURITY WARNINGS: 5 issues found on 3 hosts
```

Consultez le rapport HTML pour les détails des problèmes détectés.

---

## Résolution de Problèmes Courants

### ❌ "No interfaces detected"

**Cause** : psutil n'est pas installé

**Solution** :

```bash
pip install psutil
```

---

### ❌ Scan très lent

**Solutions** :

- Utiliser le profil quick : `--profile quick`
- Réduire les timeouts : `--ping-timeout 0.5`
- Augmenter les threads : `--threads 200`

---

### ❌ "Permission denied" sur Linux

**Cause** : ARP scan nécessite des droits root

**Solution** :

```bash
sudo python network_scanner_pro.py
```

---

### ❌ Pas de MAC address

**Cause** : Scapy n'est pas installé ou manque de droits

**Solution** :

```bash
pip install scapy
# Puis exécuter avec sudo/admin
```

---

## Profils de Scan - Comparaison

| Profil       | Durée (/24) | Ports | Usage               |
| ------------ | ----------- | ----- | ------------------- |
| **quick**    | ~30s        | 3     | Vérification rapide |
| **standard** | ~2min       | 14    | Usage quotidien     |
| **full**     | ~15min      | 1024  | Audit complet       |
| **security** | ~3min       | 18    | Audit sécurité      |

_Durées indicatives sur réseau local avec 100 threads_

---

## Bonnes Pratiques

### ✅ À FAIRE

- Scanner uniquement vos propres réseaux
- Utiliser le profil adapté à vos besoins
- Consulter régulièrement l'historique
- Exporter les rapports pour documentation
- Nettoyer la base de données périodiquement

### ❌ À ÉVITER

- Scanner des réseaux tiers sans autorisation
- Utiliser trop de threads (>500) sans raison
- Scanner en heures de pointe (impacte le réseau)
- Ignorer les alertes de sécurité
- Laisser accumuler des années de scans

---

## Performance Tips

### Pour réseaux rapides (LAN)

```bash
python network_scanner_pro.py \
  --threads 200 \
  --ping-timeout 0.5 \
  --conn-timeout 0.3
```

### Pour réseaux lents (WAN/VPN)

```bash
python network_scanner_pro.py \
  --threads 50 \
  --ping-timeout 2.0 \
  --conn-timeout 1.5
```

### Pour très grands réseaux (/16 ou plus)

```bash
python network_scanner_pro.py \
  --profile quick \
  --threads 500 \
  --no-db  # Éviter de surcharger la BDD
```

---

## Automatisation (Cron/Task Scheduler)

### Linux (crontab)

```bash
# Scan quotidien à 2h du matin
0 2 * * * /usr/bin/python3 /path/to/network_scanner_pro.py --cidr 192.168.1.0/24 --profile standard --export-csv -o /var/reports/
```

### Windows (Task Scheduler)

```powershell
# PowerShell script
$python = "C:\Python\python.exe"
$script = "C:\Scripts\network_scanner_pro.py"
& $python $script --cidr "192.168.1.0/24" --profile standard --export-csv
```

---

## Export des Données

### CSV - Pour Excel/LibreOffice

```bash
python network_scanner_pro.py --export-csv
```

Import dans Excel : Fichier > Ouvrir > Sélectionner le CSV

### JSON - Pour scripts/API

```bash
python network_scanner_pro.py --export-json
```

Utiliser avec Python, JavaScript, etc.

### HTML - Pour documentation

```bash
python network_scanner_pro.py --export-html
```

Ouvrir dans un navigateur web

---

## Support & Aide

### Obtenir de l'aide

```bash
python network_scanner_pro.py --help
python scanner_utils.py --help
```

### Activer le mode debug

```bash
python network_scanner_pro.py --debug
```

### Consulter les logs

```
~/.network_scanner_pro/scanner.log
```

---

## Prochaines Étapes

1. **Explorer les profils** : Testez quick, standard, full et security
2. **Configurer YAML** : Créez vos profils personnalisés
3. **Automatiser** : Planifiez des scans réguliers
4. **Analyser** : Utilisez les utilitaires pour comparer et suivre
5. **Documenter** : Exportez en HTML pour documentation réseau

---

**🎉 Vous êtes prêt !**

Pour plus d'informations, consultez le [README.md](README.md) complet.
