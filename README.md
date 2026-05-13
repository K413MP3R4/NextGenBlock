# NextGenBlock

**NextGenBlock est un pare-feu nouvelle génération pour Windows, conçu pour moderniser et remplacer les solutions héritées comme PeerBlock.**

NextGenBlock fournit une plateforme de sécurité réseau professionnelle : filtrage IP et DNS, inspection profonde des paquets, détection/prévention d'intrusion, géolocalisation et analyse de menaces.

## À propos

NextGenBlock a été développé pour offrir une sécurité réseau avancée aux utilisateurs Windows en associant :

- une interface moderne et ergonomique en PyQt6,
- une architecture modulaire pour les mises à jour et l’évolution,
- un moteur capable de filtrer le trafic par application, protocole et pays,
- une solution open source supportée par une licence MIT.

## Pourquoi NextGenBlock ?

PeerBlock est abandonné depuis 2014, repose sur un driver obsolète (WinPkFilter)
et ne fait que du blocage IP statique. NextGenBlock corrige ces limitations :

| Fonctionnalité            | PeerBlock | NextGenBlock |
|---------------------------|-----------|--------------|
| Blocage IP par listes     | Oui       | Oui (CIDR optimisé) |
| Pilote moderne            | Non       | WinDivert (signé, WFP) |
| IPv6                      | Non       | Oui |
| DPI / filtrage protocole  | Non       | Oui |
| Filtrage par application  | Non       | Oui (PID/exécutable) |
| IDS/IPS comportemental    | Non       | Oui |
| Filtrage DNS              | Non       | Oui (sinkhole) |
| GeoIP / blocage par pays  | Non       | Oui |
| Threat Intelligence       | Non       | Oui (flux multiples) |
| Interface moderne         | Non       | PyQt6 + graphes temps réel |
| Logs structurés / SQLite  | Non       | Oui |
| Maintenu                  | Non       | Oui |

## Architecture

```
        ┌──────────────────────────────────────────┐
        │            GUI PyQt6 (dashboard)         │
        └──────────────────┬───────────────────────┘
                           │ signaux Qt
        ┌──────────────────▼───────────────────────┐
        │          Orchestrateur (Engine)          │
        │  - file de paquets, threading sécurisé   │
        └──┬──────┬──────┬──────┬──────┬─────┬─────┘
           │      │      │      │      │     │
        ┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌─▼────┐
        │ IP  ││ DPI ││ APP ││ IDS ││ DNS ││ GEO  │
        │block││scan ││filt ││/IPS ││filt ││ /TI  │
        └──┬──┘└──┬──┘└──┬──┘└──┬──┘└──┬──┘└─┬────┘
           └──────┴──────┴──────┴──────┴─────┘
                           │
        ┌──────────────────▼───────────────────────┐
        │      WinDivert (capture noyau WFP)       │
        └──────────────────────────────────────────┘
```

## Mode sans incidence sur Internet

Par defaut, NextGenBlock demarre en mode **sans incidence reseau** : il ne
retient pas les paquets Windows et ne peut donc pas couper YouTube, les moteurs
de recherche ou le chargement des pages.

La capture reelle WinDivert doit etre activee volontairement dans les
parametres. Meme dans ce cas, le mode passif reste active par defaut : les
paquets sont observes sans etre bloques. Le mode de blocage actif affiche un
avertissement, car lui seul peut modifier le trafic reseau.

## Prérequis

- Windows 10/11 (x64)
- Python 3.10+
- Droits Administrateur uniquement si la capture reelle WinDivert est activee
- WinDivert64.sys (installé automatiquement par pydivert)

## Installation

```bash
pip install -r requirements.txt
python run.py
```

## Utilisation

Lancer normalement :

```bash
python run.py
```

Sur Windows, vous pouvez aussi double-cliquer sur `Lancer_NextGenBlock.cmd`.
Ce lanceur active automatiquement le moteur, puis cache la fenetre dans la zone
de notification apres 5 secondes. Clic gauche sur l'icone : rouvrir. Clic droit :
ouvrir, suspendre/reprendre ou quitter.

Pour creer un raccourci sur le Bureau avec le logo NextGenBlock, lancez :

```bat
Creer_Raccourci_Bureau.cmd
```

Pour lancer NextGenBlock automatiquement au demarrage de Windows, cochez
**Demarrer NextGenBlock avec Windows** dans les parametres, ou lancez :

```bat
Installer_Demarrage_Windows.cmd
```

Pour retirer ce demarrage automatique :

```bat
Desinstaller_Demarrage_Windows.cmd
```

La mise a jour automatique est non bloquante : si l'application est installee
depuis un depot Git, elle peut lancer une mise a jour en arriere-plan au
demarrage. Sinon, elle indique simplement qu'aucune source de mise a jour n'est
configuree.

## Avertissement légal

Cet outil est destiné à un usage défensif sur vos propres systèmes ou systèmes
pour lesquels vous avez l'autorisation écrite. L'utilisation pour intercepter
le trafic de tiers sans consentement est illégale dans la plupart des
juridictions.

## Licence

MIT — voir LICENSE
