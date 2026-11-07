# Mini EDR — Rapport de conception

## 1. L'équipe

> À compléter par le groupe. Les rôles ci-dessous sont repris de l'historique git, à corriger si besoin.

| Membre | Rôle |
|---|---|
| … (0xCapss) | plateforme de test (scripts, noyau), hooks BPF, SIEM Wazuh |
| … (Crysatari) | démon `edrd`, journal JSON et rotation, auto-protection du démon, `edrctl` |
| … (Picka) | durcissement de la machine (LUKS, AppArmor, PAM, pare-feu, sysctl) |
| … | … |

| Membre | Ratio |
|---|---|
| … | …% |
| … | …% |
| … | …% |
| … | …% |

## 2. Vue d'ensemble

L'EDR a trois composants, comme demandé :

- **`edr.bpf.c`** contient les programmes BPF-LSM. C'est là que se prend chaque décision (laisser passer, alerter, bloquer).
- **`edrd`** charge les programmes, les attache au boot, puis lit le ring buffer et écrit chaque événement dans `/var/log/edr.log`.
- **`edrctl`** gère les règles. Il passe par les maps épinglées dans `/sys/fs/bpf/edr/`, sans dialoguer avec le démon.

Le tout est écrit avec libbpf et CO-RE : `vmlinux.h` est généré depuis le BTF de notre noyau, et `edrd` embarque le programme BPF via un skeleton.

Deux choix guident l'architecture :

**La décision ne dépend jamais de l'espace utilisateur.** Le hook décide avant de toucher au ring buffer. Si le buffer est plein, on perd une ligne de log (comptée dans `lost_events`), jamais un blocage.

**L'EDR survit à son démon.** `edrd` épingle les liens des hooks dans `/sys/fs/bpf/edr/links/`. Si le démon est tué ou plante, les hooks restent attachés et continuent de bloquer. Au redémarrage, il réutilise les maps existantes, donc les règles posées avec `edrctl` sont conservées. `edrd` publie aussi son PID et un battement de cœur dans la map `daemon_state`, ce qui permet à `edrctl status` de distinguer un démon arrêté d'un démon figé.

## 3. Choix des hooks

Nous avons retenu six hooks, chacun lié à une étape concrète d'une attaque.

| Hook | Scénario d'attaque couvert | Réponse |
|---|---|---|
| `bprm_check_security` | L'attaquant lance un outil connu (scanner, mineur, payload déposé). | Blocage si le binaire est en liste noire |
| `socket_connect` | Un malware contacte son serveur C2, ou un reverse shell s'ouvre vers l'attaquant. | Blocage si l'IP est en liste noire |
| `inode_setattr` | L'attaquant pose un bit setuid sur une copie de shell pour se garder une porte d'entrée root. | Alerte |
| `file_open` | Vol de `/etc/shadow` pour casser les mots de passe hors ligne ; un processus compromis fouille `/etc`, `/proc` ou `/root`. | Alerte (shadow), blocage (processus confiné) |
| `task_kill` | Première chose que fait un attaquant devenu root : tuer l'EDR. | Blocage des signaux d'arrêt vers `edrd` |
| `ptrace_access_check` | S'attacher à `edrd` pour le figer ou injecter du code et le neutraliser sans le tuer. | Blocage |

Les deux derniers hooks forment l'auto-protection : un EDR qu'on éteint d'une commande ne protège rien. Seuls les signaux qui arrêtent le processus (`KILL`, `TERM`, `INT`, `QUIT`, `STOP`) sont refusés, et systemd (PID 1) garde la main. `SIGHUP` reste permis, il sert à rouvrir le journal.

Pour `inode_setattr`, nous alertons sans bloquer : poser un setuid est parfois légitime (installation de paquets), et un faux positif bloquant casserait le système.

## 4. Mécanismes de réponse

- **Blocage actif** : le hook renvoie `-EPERM`. Le programme reçoit `Operation not permitted`.
- **Confinement** (`jail_map`) : un PID confiné continue de tourner, mais ne peut plus ouvrir de fichiers sous les répertoires choisis. On peut ainsi isoler un processus suspect le temps de l'analyser, sans perdre son état en le tuant.
- **Alerte** : l'action passe, mais elle est journalisée et comptée dans `pid_stats_map`. `edrctl stats` fait ressortir les processus les plus actifs.

La liste noire d'exécutables est indexée par inode et périphérique, pas par chemin. Un chemin se contourne facilement (lien symbolique, montage, `./outil` au lieu de `/usr/bin/outil`), alors qu'un inode désigne le fichier lui-même.

## 5. Journalisation

Chaque événement devient une ligne JSON avec l'horodatage, le hook, l'action, le PID, le PPID, l'UID, le `comm` et le détail : chemin, `ip:port` ou nom du processus visé. Le `comm` et les noms de fichiers sont contrôlés par l'attaquant. Ils sont donc échappés pour qu'il soit impossible de casser une ligne ou d'en forger une fausse. Le fichier est archivé au-delà de 10 Mio (5 archives conservées).

rsyslog transmet chaque ligne au SIEM Wazuh, qui a ses propres règles pour classer les événements de l'EDR.

## 6. Plateforme et sécurité de la machine

Le noyau 7.2.8 est compilé par nos scripts avec `BPF_LSM`, `DEBUG_INFO_BTF` et `bpf` dans `CONFIG_LSM`. Il faut aussi `FUNCTION_TRACER` : les hooks BPF-LSM s'attachent par trampoline, et sans cette option l'attache échoue. Ce n'est pas du hooking ftrace, seulement un prérequis du mécanisme.

`bpf` est placé avant les autres LSM dans `CONFIG_LSM`, pour que l'EDR voie les tentatives même quand Yama ou AppArmor les auraient refusées ensuite.

Côté module de sécurité, nous avons choisi AppArmor (c'est celui qu'Ubuntu intègre) et retiré SELinux. rsyslog est confiné par son profil en mode enforce. `edrd` a un profil en mode complain, le temps de valider ses règles avant de passer en enforce. La machine est aussi durcie : racine chiffrée (LUKS), PAM, pare-feu en entrée, sysctl, lockdown `integrity`.

## 7. Scénarios de démonstration

Le guide d'utilisation détaille cinq scénarios, avec les commandes, l'alerte attendue et la vérification :

1. exécution d'un binaire en liste noire → blocage ;
2. connexion vers une IP en liste noire → blocage ;
3. pose d'un setuid par `user` → alerte ;
4. tentative de tuer `edrd` → blocage ;
5. confinement d'un shell → blocage de ses accès à `/etc`.

## 8. Limites connues

- **Contrôles Unix d'abord.** Le noyau vérifie les droits classiques avant d'appeler les LSM. Un `cat /etc/shadow` lancé par `user` est refusé avant même le hook `file_open`, qui ne le voit donc pas. L'alerte concerne les processus non root qui *ont* réellement accès au fichier. Il en va de même pour `kill` et `ptrace` sur `edrd` depuis un compte normal : ils sont refusés sans passer par l'EDR.
- **Copies non bloquées.** Bloquer par inode suit le fichier, mais une copie est un nouveau fichier. Une approche par empreinte (hash) serait plus robuste.
- **Confinement limité au PID.** Il ne s'applique pas aux fils du processus confiné.
- **Pas de persistance au reboot.** Les règles vivent dans bpffs et disparaissent au redémarrage de la machine.
- **IPv4 seulement.** C'est cohérent avec la machine, où IPv6 est désactivé.
