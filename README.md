# 🚀 NetBIOSDeprecatedFinder


**Auteur**: Ayi NEDJIMI
**Version**: 1.0
**Date**: 2025-10-20

## 📋 Description

NetBIOSDeprecatedFinder est un outil de detection d'appareils reseau exposant des protocoles deprecies et dangereux: NetBIOS et SMBv1. Il scanne une plage d'adresses IP pour identifier les machines vulnerables necessitant une mise a jour de configuration.


## ✨ Fonctionnalites

- **Scan de plage IP**: Scan parallelise d'une plage configurable d'adresses IP
- **Detection NetBIOS**: Query du service NetBIOS sur le port 137 UDP
- **Detection SMBv1**: Test de negociation SMBv1 sur le port 445 TCP
- **Plage auto**: Detection automatique de la plage IP du reseau local
- **Interface graphique**: Champ de plage IP et ListView pour les resultats
- **Scan rapide**: Utilisation de threads multiples pour accelerer le scan
- **Export CSV**: Sauvegarde des resultats avec encodage UTF-8 BOM
- **Logging**: Journalisation dans %TEMP%\WinTools_NetBIOSDeprecatedFinder_log.txt


## Compilation

### Prerequis

- Visual Studio 2019 ou superieur avec outils C++
- Windows SDK 10.0 ou superieur

### Commande de compilation

Executer `go.bat` depuis un "Developer Command Prompt for VS":

```batch
go.bat
```

Ou compiler manuellement:

```batch
cl.exe /EHsc /W4 /O2 /D UNICODE /D _UNICODE ^
    NetBIOSDeprecatedFinder.cpp ^
    /link ^
    comctl32.lib ws2_32.lib iphlpapi.lib netapi32.lib user32.lib gdi32.lib ^
    /OUT:NetBIOSDeprecatedFinder.exe
```


## 🚀 Utilisation

1. Lancer `NetBIOSDeprecatedFinder.exe`
2. Verifier/modifier la plage IP (format: 192.168.1.1-192.168.1.254)
3. Cliquer sur "Scanner" pour lancer le scan
4. Attendre la fin du scan (peut prendre plusieurs minutes selon la plage)
5. Consulter les appareils detectes dans le tableau
6. Identifier les machines avec SMBv1 actif (CRITIQUE)
7. Cliquer sur "Exporter CSV" pour sauvegarder les resultats


## Colonnes du ListView

| Colonne | Description |
|---------|-------------|
| **IP** | Adresse IP de l'appareil |
| **NetBIOS Name** | Nom NetBIOS si detecte |
| **SMBv1 Detecte** | OUI - CRITIQUE si SMBv1 actif, Non sinon |
| **Notes** | Observations et details techniques |


## Format de plage IP

La plage IP doit etre au format: `IP_DEBUT-IP_FIN`

Exemples:
- `192.168.1.1-192.168.1.254` : Reseau local classique
- `10.0.0.1-10.0.0.50` : Sous-ensemble d'un reseau
- `172.16.1.100-172.16.1.200` : Plage specifique


## Protocoles detectes

### NetBIOS (Port 137 UDP)

NetBIOS est un protocole de resolution de noms ancien et non securise. Sa presence indique:
- Systemes Windows anciens ou mal configures
- Possibilite d'attaques par spoofing de noms
- Fuite d'informations sur le reseau

### SMBv1 (Port 445 TCP)

SMBv1 est une version obsolete et dangereuse du protocole SMB:
- Vulnerabilites critiques (WannaCry, NotPetya, etc.)
- Absence de chiffrement
- Failles de securite multiples
- **DOIT ETRE DESACTIVE sur tous les systemes**


## Interpretation des resultats

### SMBv1 Detecte: OUI - CRITIQUE

Action immediate requise:
1. Identifier l'appareil (IP, hostname)
2. Desactiver SMBv1 sur le systeme
3. Mettre a jour le systeme d'exploitation
4. Verifier la configuration de securite

### SMBv1 Detecte: Non

Le systeme est probablement securise, mais verifier:
- Que SMB2/SMB3 est bien utilise si SMB est necessaire
- Que NetBIOS n'est pas expose inutilement


# 🚀 PowerShell (Administrateur)

## Commandes de remediation

### Windows 10/11 et Windows Server 2016+

Desactiver SMBv1:
```powershell
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

Verifier le statut:
```powershell
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
```

### Windows Server 2012 R2 et anterieurs

```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false
```

### Desactiver NetBIOS sur TCP/IP

Via l'interface:
1. Panneau de configuration > Reseau et Internet > Connexions reseau
2. Proprietes de l'adaptateur > TCP/IPv4 > Avance
3. Onglet WINS > "Desactiver NetBIOS sur TCP/IP"

Via PowerShell:
```powershell
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE"
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable
}
```


## 🔌 APIs Win32 utilisees

- **ws2_32.lib**: Sockets UDP/TCP pour NetBIOS et SMB
- **iphlpapi.lib**: GetAdaptersInfo pour detection de plage IP
- **netapi32.lib**: API NetBIOS
- **comctl32.lib**: ListView (LVS_REPORT)


## Architecture

- **Monolithique**: Un seul fichier .cpp
- **Unicode**: Support complet UNICODE/UTF-16
- **Threading**: std::thread pour scan parallelise (max 50 threads concurrents)
- **RAII**: Classe AutoSocket pour gestion automatique des sockets
- **Mutex**: Protection des acces concurrents aux resultats


## Format CSV

Le fichier CSV exporte contient:
- En-tete: IP;NetBIOSName;SMBv1Detected;Notes
- Encodage: UTF-8 avec BOM
- Separateur: Point-virgule (;)


## Logs

Les operations sont journalisees dans:
```
%TEMP%\WinTools_NetBIOSDeprecatedFinder_log.txt
```

Format: `YYYY-MM-DD HH:MM:SS - Message`


## ⚡ Performances

- Scan d'une plage de 254 adresses: ~2-5 minutes (selon timeouts)
- Threads concurrents: 50 maximum
- Timeout par hote: 1-2 secondes


## Limitations connues

- Ne detecte que les appareils repondant sur le reseau
- Certains pare-feu peuvent bloquer les probes
- SMBv1 peut etre actif mais protege par pare-feu (faux negatif)
- La detection NetBIOS est simplifiee (parser minimal)


## Securite

ATTENTION: L'utilisation de cet outil sur un reseau dont vous n'etes pas proprietaire peut etre consideree comme une tentative d'intrusion. Utilisez uniquement sur vos propres reseaux ou avec autorisation explicite.


## 🚀 Cas d'usage typiques

1. **Audit de securite reseau**: Identifier les machines vulnerables avant une attaque
2. **Mise en conformite**: Verifier que SMBv1 est bien desactive sur tous les systemes
3. **Migration**: Identifier les systemes anciens avant migration vers Windows 11
4. **Reponse a incident**: Detecter rapidement les vecteurs d'attaque potentiels


## Recommandations

1. Executer regulierement (mensuel) sur tous les reseaux d'entreprise
2. Remedier immediatement tous les appareils avec SMBv1 actif
3. Documenter les exceptions (si necessaires) et mettre en place des controles compensatoires
4. Desactiver NetBIOS sauf necessite absolue (applications legacy)


## 📄 Licence

Outil developpe par Ayi NEDJIMI dans le cadre de la suite WinToolsSuite.


## Support

Pour toute question ou suggestion, consulter la documentation de WinToolsSuite.


---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>