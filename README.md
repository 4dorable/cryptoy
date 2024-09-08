# Maths 2600 - Cryptoy

Ce repository contient le code à compléter pour les exercices de TPs de la dernière session sur le thème de la cryptographie.

## Mise en place

Ce projet nécessite l'installation de [poetry](https://python-poetry.org/), un outil de gestion de dépendance python plus haut niveau que `pip`.

Vous pouvez suivre la documentation pour installer poetry: [Introduction | Documentation | Poetry - Python dependency management and packaging made easy](https://python-poetry.org/docs/#osx--linux--bashonwindows-install-instructions) ⏳ 4m

Après installation, placez vous dans le repertoire du projet et lancez la commande suivante:

```bash
poetry install
```

Vous pouvez ensuite activer le script `.bashrc` pour activer l'environnement virtuel python du projet:

```bash
source .bashrc
```

## Instructions

Tous les tests définis dans `tests/*` qui doivent passer après votre implémentation.

Vous pouvez lancer tous les tests via la commande `python -m pytest`.

Ou bien lancer un seul test via la commande `python -m pytest -k [nom_du_test]`

Ajoutez l'argument `-s` pour que vos `print()` s'affiche en console.

Vous pouvez lancer un script python en interactif pour executer manuellement les fonctions de ce script, par exemple: `python -im cryptoy.caesar_cipher`.

## Modalité de rendu

Le rendu se fera via spreadsheet partagée en cours.
