# 🚀 UserAssistDecoder


**WinToolsSuite Serie 3 - Forensics Tool #21**

## 📋 Description

UserAssistDecoder est un outil forensique spécialisé pour décoder et analyser les données UserAssist du registre Windows. Ces données, encodées en ROT13, contiennent une timeline détaillée de toutes les applications exécutées par chaque utilisateur, incluant les compteurs d'exécution, timestamps, et statistiques d'utilisation.


## ✨ Fonctionnalités

### Décodage ROT13 Automatique
- **Algorithme ROT13** : Déchiffrement automatique des noms de valeurs
- **Exemple de décodage** :
  - Encodé : `HRZR_PGYFRFFVATF`
  - Décodé : `UEME_EXECUTABLES`
- **Chemins complets** : Décodage des paths d'applications (ex: `C:\Cebtenz Svyrf\...` → `C:\Program Files\...`)

### Extraction de Métadonnées
- **Run Count** : Nombre total d'exécutions de l'application
- **Last Execution Time** : Timestamp précis de la dernière exécution (FILETIME)
- **Focus Count** : Nombre de fois où l'application a eu le focus
- **Focus Time** : Temps total où l'application était au premier plan (en millisecondes)

### Support Multi-Versions Windows
- **Windows XP/Vista** : Format ancien (structure simple)
- **Windows 7/8/8.1** : Structure `USERASSIST_ENTRY_WIN7` (version 3)
- **Windows 10/11** : Structure étendue (version 5)

### GUIDs Reconnus
1. **{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}** : Executable File Execution
   - Applications lancées directement (EXE)
   - Programmes exécutés via Run dialog
   - Scripts batch, PowerShell, etc.

2. **{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}** : Shortcut File Execution
   - Raccourcis (.lnk) du menu démarrer
   - Raccourcis du bureau
   - Raccourcis de la barre des tâches

### Interface Graphique
- **ListView 8 colonnes** :
  - **Chemin Décodé** : Path complet de l'application (déchiffré)
  - **Nom Encodé (ROT13)** : Nom original encodé (pour référence)
  - **Compteur Exec** : Nombre d'exécutions
  - **Dernière Exec** : Date/heure de la dernière exécution
  - **Compteur Focus** : Nombre de fois focus
  - **Temps Focus** : Temps total au premier plan (format lisible)
  - **GUID** : Type d'exécution (Executable ou Shortcut)
  - **Username** : Nom de l'utilisateur

- **Boutons** :
  - **Scanner UserAssist** : Scan du registre HKCU\UserAssist
  - **Décoder ROT13** : Re-validation du décodage
  - **Exporter Timeline** : Export CSV UTF-8 de toutes les données
  - **Comparer Users** : Comparaison multi-utilisateurs (si accès à HKU)

### Export et Logging
- **Export CSV UTF-8** avec BOM
- **Colonnes** : Application, CheminDécodé, CompteurExéc, DernièreExéc, CompteurFocus, TempsFocus, GUID, Username
- **Logging automatique** : `UserAssistDecoder.log` (toutes opérations)


## Architecture Technique

### Clé Registry
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
```

### Structure de Données (Windows 7+)

```cpp
struct USERASSIST_ENTRY_WIN7 {
    DWORD size;              // 0x00 : Taille de la structure (72 bytes)
    DWORD version;           // 0x04 : Version (3 pour Win7, 5 pour Win10)
    DWORD runCount;          // 0x08 : Nombre d'exécutions
    DWORD focusCount;        // 0x0C : Nombre de fois focus
    DWORD focusTime;         // 0x10 : Temps total focus (ms)
    FILETIME lastExecution;  // 0x14 : Dernière exécution (8 bytes)
    DWORD unknown[10];       // 0x1C : Réservé (40 bytes)
};
```

### Algorithme ROT13

ROT13 (Rotate by 13 places) est un chiffrement par substitution simple :
- **A** → **N**, **B** → **O**, ..., **M** → **Z**
- **N** → **A**, **O** → **B**, ..., **Z** → **M**
- **Minuscules** : même rotation
- **Autres caractères** : inchangés (chiffres, ponctuation, etc.)

**Propriété** : ROT13(ROT13(x)) = x (symétrique)

### Processus de Scan

1. **Ouverture de la clé registry**
   - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

2. **Énumération des valeurs**
   - `RegEnumValueW` itérativement
   - Récupération du nom (encodé) et des données binaires

3. **Décodage ROT13 du nom**
   - Application de l'algorithme ROT13
   - Résultat : chemin complet de l'application

4. **Parsing de la structure binaire**
   - Vérification de la version (3 ou 5)
   - Extraction : runCount, focusCount, focusTime, lastExecution
   - Gestion des anciennes versions (XP/Vista)

5. **Stockage dans le vecteur**
   - Création d'un objet `UserAssistEntry`
   - Ajout à la liste principale

6. **Affichage dans la ListView**
   - Population de toutes les colonnes
   - Formatage des timestamps et durées

### Threading
- **Worker thread** pour le scan registry (évite freeze UI)
- **Message WM_USER + 1** pour signaler fin de scan
- **Enable/Disable boutons** pendant le traitement

### RAII
- **RegKey** : Wrapper RAII pour `HKEY`
  - Fermeture automatique via `RegCloseKey` dans destructeur


## 🚀 Utilisation

### Scénario 1 : Timeline Forensique Utilisateur

**Contexte** : Investigation sur les activités d'un utilisateur suspect

1. **Lancer l'outil** sur le poste de l'utilisateur (ou avec profil monté)

2. **Cliquer "Scanner UserAssist"**
   - L'outil scan automatiquement HKCU

3. **Analyser les résultats** :
   - Trier par "Dernière Exec" pour voir les activités récentes
   - Trier par "Compteur Exec" pour voir les applications les plus utilisées
   - Chercher des exécutables suspects (chemins temp, downloads, etc.)

4. **Exporter la timeline** :
   - Cliquer "Exporter Timeline"
   - Analyse approfondie dans Excel ou SIEM

### Scénario 2 : Détection de Malware

**Indices dans UserAssist** :
- **Exécutables dans Downloads/** : `C:\Users\...\Downloads\malware.exe`
- **Exécutables dans Temp/** : `C:\Users\...\AppData\Local\Temp\...`
- **Noms suspects** : `svchost.exe` (mais pas dans System32)
- **Compteur faible** : Run count = 1 ou 2 (test puis suppression)

**Exemple** :
```
Chemin Décodé: C:\Users\John\Downloads\invoice_2024.exe
Compteur Exec: 1
Dernière Exec: 15/03/2024 14:23:45
```
→ **Suspect** : EXE dans Downloads, exécuté une seule fois

### Scénario 3 : Profiling Utilisateur

**Objectif** : Comprendre les habitudes d'un utilisateur

1. **Scanner UserAssist**

2. **Cliquer "Comparer Users"** (génère rapport statistique)

3. **Analyser** :
   - Top 5 applications les plus exécutées
   - Temps total passé sur chaque application
   - Patterns d'utilisation (heures, fréquence)

**Exemple de rapport** :
```
=== Rapport de Comparaison UserAssist ===

Utilisateur : JohnDoe
  Nombre d'applications : 127
  Top 5 exécutions :
    1. C:\Program Files\Google\Chrome\chrome.exe (823 fois)
    2. C:\Windows\System32\cmd.exe (156 fois)
    3. C:\Program Files\Microsoft Office\WINWORD.EXE (89 fois)
    4. C:\Tools\Wireshark\Wireshark.exe (45 fois)
    5. C:\Program Files\Notepad++\notepad++.exe (34 fois)
```

### Scénario 4 : Investigation Insider Threat

**Contexte** : Employé suspecté de vol de données

**Recherches** :
- **Outils de transfert** : FileZilla, WinSCP, curl.exe
- **Compression** : 7-Zip, WinRAR (pour préparer exfiltration)
- **Navigation anonyme** : Tor Browser, VPN clients
- **Nettoyage de traces** : CCleaner, BleachBit

**Corrélation** :
- Timestamps des outils de compression + timestamps de transfert
- Utilisation inhabituelle d'outils réseau
- Exécution d'outils à des heures non-ouvrées

### Scénario 5 : Analyse Post-Incident

**Contexte** : Ransomware a chiffré le système

**UserAssist peut révéler** :
- L'exécutable initial du ransomware (avant chiffrement)
- Le timestamp d'exécution (début de l'infection)
- Les outils exécutés avant le ransomware (email, navigateur)

**Exemple** :
```
Chemin Décodé: C:\Users\Victim\AppData\Roaming\svchost.exe
Compteur Exec: 1
Dernière Exec: 20/03/2024 09:15:23
Focus Time: 0s
```
→ **Indicateur** : Pas de focus time = exécution silencieuse (malware)


## 🚀 Cas d'Usage Forensique

### 1. Prouver l'Exécution d'un Programme
- **Problème** : L'utilisateur nie avoir exécuté un programme
- **Solution** : UserAssist prouve l'exécution avec timestamp précis
- **Légal** : Admissible en justice (fait partie du système)

### 2. Timeline d'Activité Complète
- **Problème** : Reconstruire les actions d'un utilisateur
- **Solution** : UserAssist + Prefetch + ShimCache = timeline complète
- **Corrélation** : Croiser avec logs événements et fichiers

### 3. Détection de Lateral Movement
- **Problème** : Attaquant utilise PSExec, WMI, PowerShell
- **Solution** : UserAssist révèle l'exécution de ces outils
- **Exemple** : `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` avec run count élevé soudain

### 4. Analyse de Persistance
- **Problème** : Malware s'exécute au démarrage
- **Solution** : Run count élevé (une fois par démarrage)
- **Corrélation** : Comparer avec clés Run registry

### 5. Détection d'Outils d'Attaque
- **Outils couramment cherchés** :
  - Mimikatz
  - PsExec
  - Cobalt Strike beacon
  - BloodHound
  - PowerSploit
  - Impacket tools (psexec.py, etc.)


## 💡 ROT13 : Exemples de Décodage

### Chemins d'Applications
| Encodé (ROT13) | Décodé |
|----------------|--------|
| `P:\Cebtenz Svyrf` | `C:\Program Files` |
| `P:\Jvaqbjf\Flfgrz32` | `C:\Windows\System32` |
| `P:\Hfref\Wbua\Qbjaybnqf` | `C:\Users\John\Downloads` |
| `P:\Cebtenz Svyrf (k86)` | `C:\Program Files (x86)` |

### Applications Courantes
| Encodé (ROT13) | Décodé |
|----------------|--------|
| `HRZR_EHAPZVP` | `UEME_RUNPMIC` |
| `pzq.rkr` | `cmd.exe` |
| `abgrCnq.rkr` | `notePad.exe` |
| `pubzr.rkr` | `chrome.exe` |
| `cbjrefuryy.rkr` | `powershell.exe` |

### Commandes Spéciales
| Encodé (ROT13) | Décodé |
|----------------|--------|
| `HRZR_PGYFRFFVATF` | `UEME_EXECUTABLES` (valeur système) |
| `HRZR_EHACVPX` | `UEME_RUNPICK` (sélection dans Run) |


## Limitations et Considérations

### Limitations Techniques
1. **Données persistantes** : UserAssist survit aux redémarrages
2. **Nettoyage** : Outils comme CCleaner peuvent effacer UserAssist
3. **Taille limitée** : Cache LRU, anciennes entrées peuvent être supprimées
4. **Permissions** : Nécessite accès au profil utilisateur

### Considérations Forensiques
1. **Pas de ligne de commande** : UserAssist ne capture pas les arguments
2. **Pas de PID** : Impossible de corréler avec des processus spécifiques
3. **Timestamp unique** : Seule la dernière exécution est enregistrée (pas toutes)
4. **Focus time** : Peut être trompeur (application en arrière-plan)

### Contournements Possibles
1. **Attaquant averti** : Peut effacer UserAssist manuellement
2. **Exécution par service** : Ne génère pas d'entrée UserAssist (pas de session user)
3. **Alternate Data Streams** : Exécution via ADS peut ne pas être trackée

### Faux Positifs
1. **Focus time = 0** : Normal pour certaines applications (services, tools CLI)
2. **Run count élevé** : Normal pour applications favorites
3. **Chemins system32** : Beaucoup d'entrées légitimes


## Évolutions Futures

### Fonctionnalités Planifiées
1. **Scan multi-utilisateurs** :
   - Accès à `HKEY_USERS` (nécessite élévation)
   - Scan de tous les profils du système
   - Comparaison inter-utilisateurs

2. **Timeline graphique** :
   - Visualisation chronologique des exécutions
   - Graphes de corrélation temporelle

3. **Base de données de signatures** :
   - Détection automatique de malware connus
   - Scoring de suspicion par application

4. **Export avancé** :
   - Format JSON pour SIEM
   - Integration avec TheHive, MISP
   - Timeline MACB (plaso format)

5. **Corrélation multi-sources** :
   - Fusion avec Prefetch
   - Fusion avec ShimCache
   - Fusion avec BAM/DAM

### Améliorations Techniques
1. **Support complet HKEY_USERS** :
   - Parsing de tous les SIDs
   - Résolution SID → Username via LookupAccountSid

2. **Détection d'anomalies** :
   - Baseline normale d'utilisateur
   - Alertes sur déviations (nouveaux EXE, heures inhabituelles)

3. **Visualisation avancée** :
   - Heatmap temporelle (heures/jours d'activité)
   - Graph de co-occurrence (apps exécutées ensemble)


## Compilation

### Prérequis
- Visual Studio 2019 ou supérieur
- Windows SDK 10.0 ou supérieur
- Architecture : x86 ou x64

### Build
```batch
go.bat
```

### Fichiers Générés
- `UserAssistDecoder.exe` (exécutable principal)
- `UserAssistDecoder.log` (log runtime)


## Références Techniques

### Documentation
- [UserAssist Key Analysis](https://www.aldeid.com/wiki/Windows-userassist-keys)
- [ROT13 Wikipedia](https://en.wikipedia.org/wiki/ROT13)
- [SANS DFIR - UserAssist](https://www.sans.org/blog/userassist-forensic-analysis/)

### Outils Similaires
- **NirSoft UserAssistView** : Viewer gratuit (GUI simple)
- **Registry Explorer (Zimmerman)** : Support UserAssist intégré
- **RegRipper** : Plugin UserAssist pour parsing CLI

### Format Binaire
- **Structure Win7+** : Documentée par Didier Stevens
- **Version 3** : Windows 7/8/8.1
- **Version 5** : Windows 10/11 (structure étendue)


## 🔒 Sécurité et Confidentialité

### Données Sensibles
UserAssist contient des informations sensibles sur l'utilisateur :
- Historique complet d'exécution d'applications
- Patterns d'utilisation (heures, fréquence)
- Chemins de fichiers personnels

### Recommandations
1. **Protection des exports** : Chiffrer les CSV exportés
2. **Logging sécurisé** : Protéger le fichier `.log`
3. **Accès restreint** : Limiter qui peut exécuter l'outil
4. **Chain of custody** : Documenter toutes les analyses

### RGPD et Légalité
- **Consentement** : Analyse forensique = exception légale
- **Proportionnalité** : Limiter l'analyse au nécessaire
- **Conservation** : Définir durée de rétention des exports


## 🔧 Troubleshooting

### Problème : "Aucune donnée UserAssist trouvée"
- **Cause 1** : Utilisateur jamais connecté (profil vide)
- **Cause 2** : UserAssist désactivé (GPO entreprise)
- **Cause 3** : Données effacées par CCleaner ou similaire
- **Solution** : Vérifier manuellement la clé registry avec regedit

### Problème : "Certaines entrées ne se décodent pas correctement"
- **Cause** : Caractères spéciaux ou encodage non-standard
- **Solution** : ROT13 ne fonctionne que sur A-Z, autres caractères passent tels quels

### Problème : "Les timestamps sont dans le futur"
- **Cause** : Horloge système incorrecte lors de l'exécution
- **Solution** : Corrélation avec autres sources pour validation

### Problème : "Focus time incohérent"
- **Cause** : Application en arrière-plan ou minimisée
- **Solution** : Croiser avec d'autres métriques (run count)


## 📄 Licence

MIT License - WinToolsSuite Project


## 👤 Auteur

WinToolsSuite Development Team


## 📝 Changelog

### Version 1.0 (2025)
- Version initiale
- Support Windows XP à Windows 11
- Décodage ROT13 automatique
- Support des deux GUIDs principaux
- Export CSV UTF-8
- Interface française
- Logging complet
- Comparaison multi-utilisateurs


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>