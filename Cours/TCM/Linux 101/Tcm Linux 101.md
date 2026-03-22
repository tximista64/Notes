# Tcm Linux 101
`/etc/fstab` voir les partitions

`df -h` espace occupé sur les partitions

`du -sh` taille du dossier

`tail -f`  voir les changemments en direct sur la fin d'un fichier de log

`diff` difference entre deux fichier se faisant par majuscule

`ln -s` lien symbolic qui meure si le fichier est supprimé

`users`, `who`, `w` qui est loggé sur linux

`apt list --upgradable`

`apt show`  ==> en savoir plus sur un paquet

`printenv` => affiche les variables d'environement

`source` => update .zshrc for example

`&>`sortie et erreurs

`2>` erreure

`|&` redirige également les erreurs dans le piepe

`!!` dernière commande history

`!cat` derniere commande avec cat

comand substitution `$(comand)`

                                      or `` `comand` ``

`sort` trier

`uniq` supprimer les doublons

`wc` compter les lignes

`sed 's/SuIte/St/' sample.txt` change le mot Suite en ST dans le fichier sample.txt

`awq -F ‘,’ ‘{print $1}’ sample.txt` afficher tout avant la virgule dans le fichier

`ip -s link` ip remplace ifconfig

`ip route add` ajoute une route

`netstat -at` voir connections tcp

`netstat -lt` ports tcp en écoute

`dig -x` reverselookup avec dig

`unix2dos` convert linux text files to windows files

`dos2unix` l'inverse

Vim cheatsheet: [https://cheatography.com/typo209/cheat-sheets/comprehensive-vim-cheat-sheet/](https://cheatography.com/typo209/cheat-sheets/comprehensive-vim-cheat-sheet/)

`ps aux` | less -S

`ps -U root -u root u` => voir tout les process runnig as root 

`ps -eH` voir les process de manière hierarchique (parent-child)

ou `pstree` plus stylé

`ps` est un snapshot `top` permet de voir les processus en temps réel et leur conso

on utilise la touche d pour changer le temps de rafraichissement

`ctrlZ` suspendre un processu

`jobs` montre les processus suspendu

`bg` envoyer le processu en background

`fg` envoyer le processus en foreground

`crontab -e` modifier tache programmées

`crontab -r` supprimer tache cron

`crontab -l` lister les jobs du crontab
#hacking
