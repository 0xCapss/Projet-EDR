# Mini EDR — Guide d'utilisation

## Démarrer la machine

```
qemu-system-x86_64 -drive file=rendu/disk.qcow2,format=qcow2 -nographic -m 2G
```

Au démarrage, la machine demande la phrase de passe du disque chiffré : `Disk2600`.

| Compte | Mot de passe | Usage |
|---|---|---|
| `root` | `Ecole2600` | administre l'EDR |
| `user` | `Hacker2600` | joue l'attaquant |

## Démarrer l'EDR

Il n'y a rien à faire : `edrd` est lancé par systemd au démarrage. Pour vérifier :

```
# edrctl status
edrd:   running (pid 312, up 0h04m12s)
events: 1840 logged, 0 lost
hooks:  6 active
        bprm_check_security
        file_open
        inode_setattr
        ptrace_access_check
        socket_connect
        task_kill
rules:  0 exec, 0 ip, 0 jailed pid
```

Si besoin : `systemctl restart edrd`, et `journalctl -u edrd` pour ses messages.

Arrêter `edrd` ne désactive pas la protection : les hooks restent attachés et continuent de bloquer, seuls les logs s'arrêtent. Pour tout retirer : `systemctl stop edrd && edrd -u`.

## Utiliser edrctl

`edrctl` se lance en root. Il lit et modifie directement les maps BPF dans `/sys/fs/bpf/edr/`, il fonctionne donc même quand le démon est arrêté.

| Commande | Effet |
|---|---|
| `edrctl status` | état du démon, hooks actifs, nombre de règles |
| `edrctl watch` | alertes et blocages en temps réel (`-a` pour voir aussi chaque exécution autorisée) |
| `edrctl block add <chemin>` | interdit l'exécution de ce binaire |
| `edrctl block add <ip>` | interdit les connexions vers cette adresse IPv4 |
| `edrctl block del <chemin\|ip>` | retire la règle |
| `edrctl block list` | liste les règles |
| `edrctl jail add <pid> [etc,proc,root]` | confine un processus : il ne peut plus ouvrir de fichiers sous ces répertoires (les trois par défaut) |
| `edrctl jail del <pid>` / `jail list` | libère un processus / liste les processus confinés |
| `edrctl stats` | processus classés par nombre d'alertes et de blocages |

Bon à savoir :
- Un binaire bloqué l'est par son inode : un lien dur ou un renommage reste bloqué, mais une copie du fichier ne l'est pas.
- Les règles sont gardées quand `edrd` redémarre, mais pas au reboot de la machine.
- Le confinement vise un PID précis et ne s'applique pas aux processus fils qu'il lance.

## Lire les alertes

`edrctl watch` affiche une ligne par événement :

```
2026-11-07 19:15:02  BLOCK   bprm_check_security   pid=1234 uid=1000 comm=bash  /usr/bin/whoami
```

On y lit, dans l'ordre : la date, ce que l'EDR a fait, le hook qui a vu l'action, le processus responsable (PID, UID, nom), puis l'objet visé.

- **BLOCK** : l'action a été refusée, le programme a reçu `Operation not permitted`.
- **ALERT** : l'action a eu lieu, mais elle est suspecte.
- **info** : message du démon lui-même (démarrage, arrêt).

| Hook | Ce que ça signifie | Objet affiché |
|---|---|---|
| `bprm_check_security` | exécution d'un binaire de la liste noire | chemin du binaire |
| `socket_connect` | connexion vers une IP bloquée | `ip:port` |
| `inode_setattr` | bit setuid/setgid posé sur un fichier | nom du fichier |
| `file_open` | lecture de `/etc/shadow` par un utilisateur non root, ou fichier interdit à un processus confiné | chemin du fichier |
| `task_kill` | tentative de tuer `edrd` | `edrd` |
| `ptrace_access_check` | tentative de s'attacher à `edrd` avec ptrace | `edrd` |

Le journal complet est dans `/var/log/edr.log`, au format JSON, une ligne par événement. Il est archivé automatiquement au-delà de 10 Mio (5 archives `edr.log.1` à `edr.log.5`). Chaque ligne est aussi envoyée au SIEM Wazuh.

```
{"time":"2026-11-07T19:15:02.123456+0100","hook":"bprm_check_security","event":"exec","action":"block","pid":1234,"ppid":1180,"uid":1000,"comm":"bash","path":"/usr/bin/whoami"}
```

## Scénarios de démonstration

Une seule console suffit. Connecté en `root`, on laisse tourner `watch` en arrière-plan, puis on devient l'attaquant :

```
root# edrctl watch &
root# su - user
```

Les alertes s'affichent au fil des commandes. `exit` ramène au shell root pour les commandes `root#`.

### 1. Exécution d'un binaire interdit → blocage

```
root# edrctl block add /usr/bin/whoami
user$ whoami
-bash: /usr/bin/whoami: Operation not permitted
```

Dans `watch` : `BLOCK  bprm_check_security  ... comm=bash  /usr/bin/whoami`.
Vérification : `edrctl block list` affiche la règle. Après `edrctl block del /usr/bin/whoami`, la commande fonctionne de nouveau.

### 2. Connexion vers une IP malveillante → blocage

```
root# edrctl block add 1.1.1.1
user$ echo > /dev/tcp/1.1.1.1/80
-bash: connect: Operation not permitted
```

Dans `watch` : `BLOCK  socket_connect  ... comm=bash  1.1.1.1:80`.
Vérification : `echo > /dev/tcp/1.0.0.1/80` (adresse non bloquée) n'est pas refusé par l'EDR.

### 3. Pose d'un setuid → alerte

```
user$ cp /bin/bash /tmp/sh && chmod u+s /tmp/sh
```

La commande réussit, l'EDR ne bloque pas mais alerte : `ALERT  inode_setattr  ... comm=chmod  sh`.
Vérification : `ls -l /tmp/sh` montre le `s`, et `edrctl stats` compte une alerte pour ce processus.

### 4. Tentative de tuer l'EDR → blocage

Un utilisateur normal ne peut déjà pas tuer un processus root, donc ce scénario suppose un attaquant qui a obtenu root :

```
root# kill -9 $(pidof edrd)
bash: kill: (312) - Operation not permitted
```

Dans `watch` : `BLOCK  task_kill  ... comm=bash  edrd`.
Vérification : `edrctl status` indique toujours `running` avec le même PID. Les signaux non destructifs passent toujours (`kill -HUP` rouvre le journal).

### 5. Confinement d'un processus

```
user$ echo $$
1180
root# edrctl jail add 1180 etc
user$ read line < /etc/hostname
-bash: /etc/hostname: Operation not permitted
```

Dans `watch` : `BLOCK  file_open  ... pid=1180 comm=bash  /etc/hostname`. La redirection est faite par le shell lui-même : un `cat` lancé depuis ce shell a son propre PID et n'est pas confiné.
Vérification : `edrctl jail list`, puis `edrctl jail del 1180` rend l'accès.
