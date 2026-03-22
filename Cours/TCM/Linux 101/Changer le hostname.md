# Changer le hostname
Changer le hostname
-------------------

Il faut suffit tout simplement d’éditer le fichier **/etc/hostname** avec votre éditeur préféré (vi, vim, nano) et de changer le nom de la machine.

Une fois changé vous pouvez vérifier le changement en exécutant la commande _hostname_

```text-plain
$ hostname
kimsufi
```

Nous avons un nom plus explicite.

Il faut ensuite éditer le fichier _**/etc/hosts**_ pour éviter l’erreur suivante: **unable to resolve host : Name or service not known** lorsque vous faite un sudo.   
Exemple

```text-plain
$ sudo true
unable to resolve host kimsufi: Name or service not known
```

Editer le fichier /etc/hosts
----------------------------

Il faut maintenant ajouter une entrée localhost dans le fichier _**/etc/hosts**_ avec le nouveau hostname défini.  
Editer votre fichier avec les droits sudo avec la commande _**sudo vim /etc/hosts**_ par exemple et ajouter une nouvelle ligne pour avoir ce résultat:

```text-plain
# Do not remove the following line, or various programs
# that require network functionality will fail.
127.0.0.1 localhost.localdomain localhost
127.0.0.1 kimsufi
```

Maintenant la commande _**sudo true**_ ne vous retourne plus d’erreur.
#hacking
