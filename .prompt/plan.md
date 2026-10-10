# Plan - Forgejo Kubernetes Operator

Pendant de `batleforc/weebo-authentik` pour Forgejo. Ce document est la
source de vérité de conception (scope CRD, conventions d'erreur, modèle de
status, politique de mutation, tests, CI). `CLAUDE.md` l'indexe ; toute
modification non triviale doit d'abord être cohérente avec ce plan (ou le
faire évoluer explicitement).

Les décisions ci-dessous ont été tranchées lors d'une session de
"grilling" (2026-10-06). Quand un choix diverge volontairement de
weebo-authentik, c'est signalé par **(≠ authentik)**.

## Périmètre

- L'opérateur gère des **objets à l'intérieur d'une instance Forgejo
  existante** (orgs, équipes, dépôts, utilisateurs, clés, webhooks,
  applications OAuth2, tokens). Il ne déploie **pas** Forgejo lui-même :
  le cycle de vie de Forgejo reste au chart Helm officiel.
- **Version cible : Forgejo ≥ v16.** Raison structurante : l'API
  `POST/DELETE /admin/users/{u}/tokens` (création de token par un admin
  pour un autre utilisateur) n'existe qu'à partir de v16. Sur la LTS v11,
  la création de token exige le mot de passe de l'utilisateur en Basic
  auth (`reqBasicOrRevProxyAuth`), le `Sudo` est refusé — un second chemin
  de code moins sûr qu'on refuse de maintenir.
- **Sources d'authentification (OIDC Authentik) : hors opérateur.** Aucune
  API REST n'existe (ni v11 ni main) ; elles sont configurées via le chart
  Helm Forgejo (`gitea.oauth[]`) ou `forgejo admin auth add-oauth`.
  L'opérateur ne fait que les **référencer** (`ForgejoUser.spec.loginSourceId`).
  **Par id numérique, pas par nom** : constaté en M1, Forgejo n'expose
  aucune route listant les sources d'authentification, un nom ne peut donc
  pas être résolu. L'id est visible dans Administration du site → Sources
  d'authentification.
- **Reporté (post-v1)** : Forgejo Actions (`ActionsSecret`,
  `ActionsVariable`, token d'enregistrement de runner).

## CRDs (v1)

Groupe `forgejo.weebo.io`, version `v1alpha1`. Finalizer
`forgejo.weebo.io/finalizer`. Chaque CRD a un shortname et des
printcolumns `Ready` / `ID` / `Age` **(≠ authentik, qui n'en a pas)**.

| Kind | Scope | Short | Rôle |
|---|---|---|---|
| `ForgejoInstance` | cluster | `fji` | Connexion : `url`, `tokenSecretRef{name,namespace,key}` (token admin), `tls{insecureSkipVerify, caSecretRef}`, `secretStore{backend: kubernetes\|vault, vault{…}}` |
| `ForgejoUser` | cluster | `fjuser` | Utilisateur (3 modes, cf. ci-dessous) |
| `ForgejoUserKey` | cluster | `fjukey` | Clé SSH publique d'un `ForgejoUser` (`/admin/users/{u}/keys`) |
| `ForgejoOrganization` | cluster | `fjorg` | Organisation (`/orgs`, `/admin/users/{u}/orgs`) |
| `ForgejoTeam` | cluster | `fjteam` | Équipe d'une org : `permission`, `unitsMap`, `includesAllRepositories`, `canCreateOrgRepo`, `memberRefs[]` (l'accès aux dépôts se déclare côté dépôt, cf. M2) |
| `ForgejoNamespacePolicy` | cluster | `fjnp` | Allow-list : quels namespaces peuvent créer quelles kinds, dans quelles orgs |
| `ForgejoRepository` | namespaced | `fjrepo` | Dépôt : création (vide / auto-init / template), pull-mirror/migrate, settings, archive, branch protections, `teamRefs[]` |
| `ForgejoWebhook` | namespaced | `fjhook` | Webhook repo ou org |
| `ForgejoDeployKey` | namespaced | `fjdkey` | Clé de déploiement d'un dépôt ; peut générer la paire et écrire la privée dans `secretTargets` |
| `ForgejoOAuth2Application` | namespaced | `fjoauth` | App OAuth2 ; client id/secret écrits dans `secretTargets` |
| `ForgejoAccessToken` | namespaced | `fjtoken` | Token d'accès d'un utilisateur ; valeur écrite dans `secretTargets` |

Découpage du scope (même logique qu'authentik) : les objets d'**identité /
structure partagée** sont cluster-scoped ; les objets **possédés par une
équipe applicative** ou **qui produisent un Secret** sont namespaced, et
c'est ce que l'allow-list gouverne.

### Instance par défaut

Comme authentik : `instanceRef` optionnel. Absent → il doit exister
**exactement une** `ForgejoInstance`, sinon `Ready: False` /
`AmbiguousDefaultInstance` (ou `InstanceNotFound` s'il n'y en a aucune).
Les `ForgejoInstance` sont mises en cache dans un reflector partagé.

### Références

- Toujours **par nom de CR** (`organizationRef: {name}`,
  `userRef: {name}`, `repositoryRef: {name}`…), jamais par nom brut
  Forgejo. Garde l'allow-list et le graphe de dépendance cohérents.
- Une CR namespaced peut référencer une CR cluster-scoped, ou une CR
  namespaced **de son propre namespace** uniquement.
- Les controllers déclarent des `watches` sur les kinds référencées :
  une CR en attente d'une référence non prête est réveillée dès que la
  référence passe `Ready` (pas d'attente du requeue 30 s).

### ForgejoUser : trois modes

- **Externe (pré-provisionné)** : `loginSourceId` (id numérique de la source
  OIDC) + `loginName` (défaut : `username`). Pas de mot de passe. Forgejo
  rattache le compte au premier login OIDC.
- **Local / bot** : mot de passe aléatoire généré et écrit dans
  `secretTargets`, `mustChangePassword` configurable. `bot: true` ⇒ le mot
  de passe est généré puis **jeté** (jamais émis) : compte utilisable
  uniquement via tokens et clés SSH. **Pas** `prohibit_login` — constaté en
  M3, Forgejo refuse aussi les tokens API d'un compte prohibé (403). Un
  champ `prohibitLogin` explicite reste disponible pour désactiver un compte.
  De même, `must_change_password` bloque les tokens API (403 « You must
  change your password ») : jamais posé sur un bot.
- **Observé** : `managementPolicy: Observe`. L'opérateur ne crée, ne
  modifie et ne supprime **jamais** l'utilisateur ; il le résout par
  `username` et publie son id. Sert à référencer un utilisateur
  **auto-créé par Forgejo au premier login OIDC**. Tant qu'il n'existe
  pas : `Ready: False` / `UserNotFound`, re-vérifié toutes les 30 s.
  Une `ForgejoTeam` dont un membre est dans cet état pose
  `MemberPending` (Advisory) et synchronise quand même les autres
  membres.

Suppression d'un utilisateur : jamais `purge=true`.

**Membres d'équipe venant des groupes OIDC** : `ForgejoTeam.spec.membersPolicy`
= `Managed` (défaut, `memberRefs` autoritaire) | `External` (l'opérateur
ne touche jamais aux membres ; `memberRefs` non vide ⇒ `InvalidSpec`, sans
appel Forgejo). Les membres viennent alors de la synchro groupe → équipe
de la source d'authentification (`group-team-map`, `dyn-group-maps`),
configurée hors opérateur. Constats (code Forgejo 16.0.5,
`services/auth/source/source_group_sync.go`) : synchro **uniquement au
login web OIDC** (révocation différée : tokens et clés SSH restent
valides jusque-là) ; org et équipe doivent exister (sinon warning et
ignorées) ; `group-team-map-removal` ne retire que des équipes mappées,
mais `dyn-group-maps-removal` retire de **toutes** les équipes non
mappées (y compris `Owners` et les équipes `Managed`). La source est
relue en base à chaque login : un `update-oauth` prend effet sans
redémarrage (sauf le cache des `dyn-group-maps` au premier login).

Configuration recommandée (guide `oidc-groups`) : une **convention de
nommage** posée une fois dans le chart Forgejo, `dynGroupMaps:
'["forgejo/{org}/{team}"]'`, pour qu'une nouvelle équipe ne demande
qu'une `ForgejoTeam` `External` et un groupe chez l'IdP — jamais de
`helm upgrade` ni de redémarrage. Constats (chart forgejo-helm 17.2.0,
Forgejo 16.0.5 réel + IdP OIDC de test) : le chart rejoue `update-oauth`
à chaque démarrage, n'écrase que les options qu'il passe ; il rend
`dynGroupMapsRemoval: true` en `--dyn-group-maps-removal "true"`, que la
CLI refuse (`unexpected arguments`) ⇒ init en échec : l'option s'active
une fois à la main (`kubectl exec … update-oauth --dyn-group-maps-removal`)
et survit aux redémarrages. `scopes` doit inclure `profile` (Forgejo ne
demande que `openid` par défaut ; Authentik met `groups` dans `profile`),
séparés par des virgules, relus au démarrage seulement.

Écarté : l'opérateur qui écrit `group-team-map` via `kubectl exec`
(`pods/exec` sur Forgejo = accès à `app.ini`, CLI non stable). **Piste
future** si le délai de révocation (au login) devient bloquant :
`membersPolicy: Group` + `groupRef` vers un `AuthentikGroup`
(weebo-authentik), l'opérateur calculant les membres lui-même —
révocation au reconcile, plus de config côté Forgejo, au prix d'un
couplage entre les deux opérateurs.

### Propriété des objets "par utilisateur" (Sudo)

L'API OAuth2 (`/user/applications/oauth2`) est strictement scoppée à
l'appelant (`ctx.Doer()`), sans équivalent admin/org. L'opérateur agit
donc en **`Sudo`** (header supporté pour les tokens admin) :
`ForgejoOAuth2Application.spec.ownerRef` → un `ForgejoUser` (typiquement
un bot `prohibit_login`) ; absent ⇒ l'utilisateur admin de l'instance.
L'opérateur n'a jamais besoin des credentials de l'utilisateur cible.
Le token admin doit porter les scopes couvrant l'action impersonnée.

### ForgejoOAuth2Application : secret et rotation

Chaque `PATCH` d'une app régénère le `client_secret` (et il n'est jamais
relisible via GET). Donc :

- Le reconciler ne PATCH **que si le spec diffère réellement** de l'état
  Forgejo (nom, `confidentialClient`, `redirectUris`) — jamais un PATCH
  aveugle à chaque requeue.
- Le secret retourné est immédiatement poussé vers `secretTargets`
  (`FORGEJO_CLIENT_ID`, `FORGEJO_CLIENT_SECRET`, `FORGEJO_URL`).
- Rotation explicite via l'annotation `forgejo.weebo.io/rotate-secret:
  <nonce>` : un nonce différent de `status.lastRotation` déclenche un
  PATCH à l'identique.
- Secret cible absent alors que l'app existe ⇒ rotation (seul moyen de
  ré-obtenir une valeur).

### ForgejoAccessToken

- Créé via `POST /admin/users/{u}/tokens` (v16+), `scopes` +
  `repositories[]` optionnel. Valeur retournée une seule fois → écrite
  dans `secretTargets` (`FORGEJO_TOKEN`, `FORGEJO_URL`).
- Token supprimé côté Forgejo (détection par nom) ou Secret cible
  disparu ⇒ recréation.
- Rotation : annotation `forgejo.weebo.io/rotate-secret` ou
  `spec.rotationPeriod` (durée) comparé à `status.lastRotation`.
- Changement de `scopes` = delete-recreate = **disruptif** (cf. politique
  de mutation).
- Ordre d'une rotation : **émettre le nouveau, l'écrire partout, puis
  révoquer l'ancien** (le token alterne entre `name` et `name-next`, les
  noms étant uniques par utilisateur). Écriture ratée : le nouveau est
  révoqué, l'ancien reste valide, `secretPending` relance.

### ForgejoRepository (v1)

- Création : vide, `autoInit` (README/gitignore/licence), ou depuis un
  template (`templateRef` → `POST /repos/{o}/{r}/generate`).
- Migration / pull-mirror : `migrate{cloneAddr, service, mirror,
  mirrorInterval, lfs, authSecretRef}` → `POST /repos/migrate`.
- Settings : visibilité, branche par défaut, unités (issues, wiki, PR…),
  `archived`.
- Branch protections : `branchProtections[]` (CRUD sur
  `/repos/{o}/{r}/branch_protections`).
- **Pas de collaborateurs** : l'accès passe par les équipes, déclarées
  **côté dépôt** (`teamRefs`, décision M2 — à la place du
  `ForgejoTeam.repositoryRefs` prévu). Raisons : une `ForgejoTeam`
  cluster-scoped pointant vers des dépôts namespaced violerait la règle des
  références (cluster ou même namespace), et c'est le namespace
  propriétaire du dépôt qui doit décider de son accès — exactement la
  frontière que l'allow-list du M4 gouverne. Liste autoritaire, sauf
  l'équipe `Owners` et les équipes `includesAllRepositories`, que Forgejo
  accorde d'office.
- Changer `owner` = **transfert** (`POST /repos/{o}/{r}/transfer`, garde
  l'historique) = disruptif, gaté par l'annotation.
- Suivi **par id** (`GET /repositories/{id}`) : renommages et transferts ne
  perdent jamais le dépôt (pas de piège de redirection comme pour users/orgs).
- Branch protections : listes d'autorisation en **noms Forgejo bruts**
  (utilisateurs, équipes), exception assumée à « références par CR » — une
  CR par nom serait lourde sans bénéfice. Liste autoritaire (une règle
  absente du spec est supprimée).

### Constats du M1 (vérifiés contre un Forgejo 16.0.5 réel)

- **Redirections après renommage** : `GET /users/{ancien}` et
  `GET /orgs/{ancien}` répondent encore après un rename (redirection vers le
  nouveau nom). Le gateway traite une réponse dont le login/nom diffère de
  celui demandé comme « absent » — sinon un utilisateur observé pourrait se
  résoudre vers un compte renommé.
- **Équipe sans unités refusée** : un team non-admin sans `units_map` est
  rejeté (« units permission should not be empty », en **500**).
  `unitsMap` vide ⇒ toutes les unités dépôt (hors `ext_*`, lecture seule) au
  niveau de `permission`, comme le fait l'UI Forgejo. Aller-retour exact
  vérifié : pas de PATCH en régime établi.
- **Conflits de nom** : 422 (et non 409) pour users/orgs/teams ; 422 sert
  aussi aux erreurs de validation, d'où la classification sur le message
  (`already exist`).
- **Mot de passe local non relisible** : si une cible de `secretTargets`
  disparaît, le mot de passe est réinitialisé (seul moyen de le
  redistribuer). L'id Forgejo est persisté même si l'écriture du secret
  échoue juste après la création — jamais de seconde création.
- **Bots** : Forgejo exige un mot de passe pour tout compte local ; celui
  d'un bot est généré puis jeté (inutilisable par quiconque).
- `secretTargets` vers Vault refusés (`InvalidSpec`) jusqu'au M3 ; seules
  les cibles Kubernetes existent en M1.

### Constats du M2 (vérifiés contre un Forgejo 16.0.5 réel)

- **Équipe d'allow-list sans accès ignorée** : une équipe listée dans
  `push_whitelist_teams` sans accès en écriture au dépôt est silencieusement
  retirée par Forgejo → diff perpétuel. Le reconciler synchronise donc les
  `teamRefs` **avant** les branch protections.
- **`mirror_interval` renvoyé en forme Go canonique** (`8h` → `8h0m0s`) :
  comparaison en secondes.
- **Dépôts archivés** : la plupart des écritures sont refusées (423). Tant
  que le spec garde `archived: true`, le dépôt est « gelé » (Ready, aucun
  appel) ; désarchiver passe en premier, archiver en dernier.
- **Migration synchrone** : `POST /repos/migrate` (et `generate`) clone dans
  la requête → client HTTP dédié avec un timeout de 15 min (un timeout
  laisserait un dépôt à moitié importé contre lequel le reconcile suivant
  entrerait en collision).
- **Secret de webhook en écriture seule** : jamais relu ; son empreinte
  SHA-256 (avec l'en-tête d'autorisation) est gardée dans
  `status.appliedSecretHash` pour détecter une rotation du `Secret`.
  L'édition d'un hook (Forgejo 16) ignore le secret et toute clé de
  `config` non relue (`http_method`…) : leur changement recrée le hook
  (comme un changement de type). Format `v2:<create-only>:<en-tête>`,
  toujours renseigné ; l'en-tête, lui, s'édite en place.
- **Clés SSH immuables** : tout changement (titre, clé, lecture seule) =
  suppression + recréation. Sans `publicKey`, paire ed25519 générée, clé
  privée écrite dans `secretTargets` (`ssh-privatekey`/`ssh-publickey`,
  noms de `kubernetes.io/ssh-auth`) ; cible disparue ou nouveau nonce
  `rotate-secret` ⇒ nouvelle paire. Comparaison sur algorithme + matériau
  (Forgejo ne garde pas le commentaire).

### Constats du M3 (vérifiés contre un Forgejo 16.0.5 réel)

- **`prohibit_login` bloque aussi les tokens API** (403 « This account is
  prohibited from signing in »), et **`must_change_password` aussi** (403
  « You must change your password »). D'où le changement de `bot: true` :
  mot de passe aléatoire jamais émis, ni `prohibit_login` ni
  `must_change_password` (cf. « ForgejoUser : trois modes »).
- **`Sudo` fonctionne pour les apps OAuth2**, y compris vers un compte
  prohibé. Le patch de spec `spec/patches/20-oauth2-sudo-header.jq` déclare
  un paramètre d'en-tête `Sudo` explicite sur les seules routes
  `/user/applications/oauth2*` : le client généré l'expose par appel, sans
  le réintroduire comme schéma de sécurité global.
- **Nom de token déjà pris = 400** (« has been used already ») et non 409/422
  : la classification « already exists » couvre 400/422 sur le message.
- Un app OAuth2 appartenant au bot est **invisible** à l'admin sans `Sudo`
  (scoping strict à l'appelant, confirmé).
- Scopes de token relus tels qu'envoyés (pas de normalisation côté Forgejo).

### Stockage des secrets (M3)

`ForgejoSecretStoreFactory` construit, par `ForgejoInstance`, un
`RoutingSecretStore` : chaque `SecretTarget` part vers son backend
(`kubernetes` → Secret en server-side apply ; `vault` → KV v2, chemin
`path` explicite ou `<pathPrefix>/<namespace>/<name>`). Un Vault en panne
ne bloque que les cibles Vault. Login Kubernetes-auth mis en cache 80 % du
lease, re-login unique sur 401/403, écriture KV sautée si le document est
identique (pas de nouvelle version). Sans `secretTargets` (OAuth2, token),
une cible implicite : nom de la CR, son namespace, backend par défaut de
l'instance.

### Constats du M4

- **Accès Secrets cluster-wide** signalé par trivy (KSV-0041, CRITICAL) :
  accepté et documenté dans `.trivyignore.yaml` (scopé au ClusterRole) —
  écrire les credentials dans le namespace que chaque CR désigne *est* la
  fonctionnalité ; l'allow-list et le RBAC namespaced bornent qui peut
  demander quoi.
- **Docs** : Fumadocs repris d'authentik et mis à jour (fumadocs 16.16,
  Next 16.4). `npm audit` ne gate que les dépendances de prod du site :
  la seule alerte (braces ≤ 3.0.3 via `eslint-config-next`, outillage de
  lint) n'a pas de version corrigée publiée.
- **kind sur podman rootless** ne démarre pas sur ce poste (pas de cible
  systemd « Multi-User » dans le nœud, même avec `Delegate=yes`) : le test
  du chart en cluster réel est reporté à l'e2e kind en CI (M5). Couvert
  localement : rendu/lint du chart, image construite et démarrée, routeur
  du webhook contre un vrai apiserver (envtest) avec de vraies policies.

### Constats du M5

- **Importer = use-case + port dédié** : `application::use_cases::import`
  construit les CR depuis un port `ForgejoInventory` (listes paginées,
  supertrait de `ForgejoGateway`, implémenté par `ForgejoHttpGateway` et
  `FakeForgejo`) ; les reconcilers n'énumèrent jamais. `crates/importer`
  n'est que le CLI (`weebo-forgejo-importer`, livré dans les deux images).
- **Seeding du status sans course** : `status` est une sous-ressource,
  donc création puis patch. Entre les deux, un reconcile créerait un
  doublon pour les webhooks (aucun nom unique, pas de 409). La CR est donc
  créée avec l'annotation `forgejo.weebo.io/import-pending` (les
  controllers des kinds importables l'ignorent, sauf suppression), le
  status est écrit, puis l'annotation retirée. Ré-exécution idempotente
  (même `forgejoId` = ignorée ; autre id = erreur, CR intacte).
- **Pas d'adoption par annotation** : écrire un id dans une annotation
  rendrait l'adoption déclarative (GitOps) mais permettrait à tout
  namespace autorisé de détourner n'importe quel objet Forgejo par son id.
  Le seeding exige le droit `patch` sur `status`, que l'allow-list ne
  délègue pas.
- **Valeurs par défaut non destructives** : tout ce qui est importé est
  `deletionPolicy: Orphan` ; les users sont `Observe` (avec
  `--manage-users`, un compte local devient `bot: true` : mot de passe
  inconnu, jamais réinitialisé) ; webhooks sans `secretRef` (le secret
  existant reste : l'édition d'un hook ne le touche jamais). OAuth2 et tokens non
  importés (secrets illisibles).
- **Vérifié contre Forgejo 16.0.5** : le reconcile des CR importées
  (org, équipe avec unités, dépôt avec protection + accès d'équipe,
  webhook, clé) n'envoie que des GET. `GET /orgs/{org}/teams` n'embarque
  pas l'organisation : l'adapter la renseigne.
- **Leader election** extraite dans `operator::leader` (acquire / hold)
  et testée sur envtest : perte du lease signalée au renouvellement
  suivant, puis reprise par l'autre réplica après le TTL.
- **Release** : un tag poussé avec `GITHUB_TOKEN` ne déclenche aucun
  workflow ; `release.yml` appelle donc `publish.yml` (devenu
  `workflow_call`). `cargo update --offline` du hook de bump échoue sur un
  runner vierge : repli en ligne. Les images sont lancées
  (`weebo-forgejo-importer --version`) en CI et après publication.
- **e2e kind** (`task e2e`, `deploy/e2e/run.sh`, hebdo) : toujours
  impossible localement (kind sur podman rootless), d'abord exécuté en CI.

### Durcissement « prod ready » (revue d'octobre 2026)

- **Secrets émis** : un CR namespacé n'écrit que dans **son** namespace
  (`CrossNamespaceReference`, webhook + reconciler) et, sur Vault, sous
  `<pathPrefix>/<namespace>/`. Les stores ne modifient/suppriment que ce
  qu'ils possèdent : label `managed-by` + annotation
  `forgejo.weebo.io/owner: <Kind>/<ns>/<name>` (Vault : `custom_metadata`).
- **Identifiants d'admin** : token / app OAuth2 d'un `ForgejoUser`
  `admin: true` (ou `@instance-admin`) refusés sauf règle `Allow` qui le
  nomme dans `allowedUsers` — **même sans aucune policy**.
- **Résolution par id** : utilisateurs et organisations renommés hors
  opérateur sont retrouvés par id (renommés en retour, supprimés par id),
  jamais recréés à côté ni confondus avec un homonyme.
- `spec.instanceRef` **immuable** (règle CEL) ; règles CEL pour les
  « exactement un de » (repo, webhook, clés, team External, email).
- `ForgejoInstance` a un finalizer tant que des CR y sont liés ;
  `forgejo.weebo.io/force-orphan: "true"` libère un CR sans cleanup ;
  un cleanup raté émet un Event `Warning` (action `Cleanup`, raison de
  l'échec) ; toute erreur et tout changement d'état du CR émettent un
  Event (`weebo_kit_runtime::events`, `Bound`/`Released`).
- Webhooks (même URL) et apps OAuth2 (même nom) : jamais de jumeau à la
  création (`ForgejoObjectAlreadyExists`) ; patch de status retenté.
- `appliedSecretHash` v3 : salé par CR + étiré (migration v2/legacy auto).
- Leader election du kit (v0.2.0) : `resourceVersion` sur chaque écriture
  du Lease, horloge monotone locale ; nom par défaut inchangé.
- Contrôleurs : concurrence bornée, filtre generation/annotations/labels/
  finalizers/deletion, backoff avec jitter, échecs « à changement requis »
  relancés à 300 s ; appels Forgejo bornés par instance + métriques
  `weebo_forgejo_forgejo_*` ; `/metrics` Prometheus, `/readyz` `/livez`.

## Convention d'erreurs : codes stables

Identique à authentik : **aucune chaîne de raison en dur au point
d'appel.** Un seul enum `domain::error::ReasonCode` avec `as_str()`
(PascalCase) et `severity()` (`Blocking | Advisory`). Les helpers de
condition / `Event` / refus webhook n'acceptent que `ReasonCode`.

Catalogue initial (à étendre uniquement dans l'enum) : `Reconciled`,
`InstanceNotFound`, `AmbiguousDefaultInstance`, `InstanceUnreachable`,
`TokenSecretNotFound`, `ForgejoObjectAlreadyExists`, `ForgejoApiError`,
`ReferenceNotFound`, `ReferenceNotReady`, `UserNotFound`,
`MemberPending`, `LoginSourceNotFound`, `DisruptiveUpdateRefused`,
`NamespaceNotAllowed`, `CrossNamespaceReference`, `SecretTargetFailed`,
`InvalidSpec`, `UnsupportedForgejoVersion` (instance < v16, ajouté en M1),
`KubernetesApiError` (apiserver en échec pendant la résolution de
l'instance : transitoire, plus confondu avec `InvalidSpec`).

## Modèle de status commun

```
status:
  observedGeneration: int64
  forgejoId: string | null     # PK côté Forgejo ; présent = cette CR possède l'objet
  lastRotation: string | null  # nonce/horodatage de la dernière rotation (OAuth2, token)
  conditions:
    - type: Ready
      status: "True" | "False" | "Unknown"
      reason: ReasonCode
      message: string
      lastTransitionTime: timestamp
      observedGeneration: int64
```

Patch merge sur la sous-ressource status, field manager
`weebo-forgejo-operator`. **Relecture fraîche** de l'objet (GET direct à
l'API, pas le cache du watch) avant d'utiliser `forgejoId` — évite les
doubles créations observées dans authentik. Des `Event` Kubernetes sont
émis à chaque transition **(≠ authentik, prévu mais jamais livré là-bas)**.

### Collision avec un objet existant → rejet, jamais d'adoption implicite

1. Le reconciler tente directement la **création** (pas de
   lookup-puis-create).
2. Succès → PK écrit dans `status.forgejoId`.
3. Conflit (409/422 nom pris) → `Ready: False` /
   `ForgejoObjectAlreadyExists`, `Event`, pas de retry serré.
4. **Seul chemin d'adoption** : l'outil `importer` qui génère la CR à
   partir de l'état Forgejo réel et y inscrit `forgejoId`.

Exception : `ForgejoUser` en `managementPolicy: Observe`, qui par
définition ne crée rien.

## Politique de mutation

- **La CR est autoritative** : chaque reconcile compare spec et état
  Forgejo, envoie un PATCH si diff. Requeue 300 s en succès, 30 s en
  erreur.
- Delete-recreate uniquement quand un PATCH est structurellement
  impossible (transfert de dépôt, changement de scopes d'un token,
  changement d'owner d'une app OAuth2). Exige l'annotation
  `forgejo.weebo.io/allow-disruptive-update: "true"`, sinon
  `Ready: False` / `DisruptiveUpdateRefused`.

### Politique de suppression **(≠ authentik)**

`spec.deletionPolicy: Delete | Orphan` sur chaque CRD. Défauts :

- `Orphan` pour `ForgejoRepository`, `ForgejoOrganization`, `ForgejoUser`
  (supprimer une CR ne doit jamais détruire de l'historique git ni
  l'attribution des commits).
- `Delete` pour tout le reste.

## Stockage des secrets

Repris tel quel d'authentik : `secretTargets[]` (fan-out K8s Secret +
Vault KV v2 / Kubernetes auth), défaut = `ForgejoInstance.spec.secretStore`.
Secret K8s écrit en server-side apply, sans ownerReference, supprimé
explicitement au finalizer.

## Sécurité opérationnelle & déploiement

Identique à authentik :
- Webhook d'admission `failurePolicy: Fail`, `CREATE`/`UPDATE` seulement
  (jamais `DELETE`), servi sur tous les replicas, cert cert-manager relu
  toutes les 60 s.
- `ForgejoNamespacePolicy` : allow tant qu'aucune policy n'existe,
  default-deny dès qu'une existe. Règles `{namespaces, allowedKinds,
  allowedOrganizations, allowedUsers, effect}` **(≠ authentik)** :
  - `namespaces` : noms exacts, `*`, ou glob préfixe (`team-*`).
  - `allowedOrganizations` / `allowedUsers` (noms de CR ; absent = tout) :
    un `Allow` doit couvrir **toutes** les orgs et users référencés par la
    CR (owner d'un dépôt, org d'un webhook d'org, owner d'une app OAuth2,
    titulaire d'un token). `allowedUsers` est ce qui empêche un namespace
    de frapper un token pour un compte privilégié (ajouté en M4 : sans lui,
    `ForgejoAccessToken` était une escalade de privilèges).
  - Un `Deny` matche namespace + kind, restreint par ses listes si posées ;
    deny gagne toujours.
  - Même code (`application::use_cases::admission::check`, logique pure
    dans `domain::allow_list`) pour le webhook et pour la re-vérification
    de **chaque** reconciler namespaced avant tout appel Forgejo ; les
    controllers watchent les policies, un changement re-réconcilie tout.
  - Webhook servi seulement si le certificat est monté (désactivé avec un
    warning en local) ; `/healthz` pour les probes.
- Leader election par `Lease` (TTL 15 s, renew 5 s), exit si perte.
- Chart Helm : 2 replicas, PDB, Certificate/Issuer, ClusterRole, Role
  exemple namespaced, `health.lua` ArgoCD.

## Observabilité

`tracing` + OTLP (traces + métriques) activé si
`OTEL_EXPORTER_OTLP_ENDPOINT` est défini. Métriques
`weebo_forgejo_reconcile_total{kind,result,reason}` et
`weebo_forgejo_reconcile_duration_seconds`.

## Architecture hexagonale

La plomberie commune aux opérateurs weebo vit dans
**weebo-operator-kit** (repo voisin, plan dans son `docs/plan.md`) :
codes de raison, moteur d'allow-list, sous-types de CRD partagés,
secret stores Kubernetes/Vault, télémétrie, leader election, serveur
webhook TLS, conditions/Events, métriques, envtest. Les crates
ci-dessous n'en gardent que la partie propre à Forgejo.

Workspace Cargo (edition 2024), versions centralisées dans
`[workspace.dependencies]` :

- `crates/domain` — logique pure (`ReasonCode`, conditions, allow-list,
  calcul de diff). Zéro `kube`/`http`.
- `crates/api` — types CRD (`kube::CustomResource`). One-of = struct
  plate + discriminant (`kind`/`backend`), jamais enum taggé (kube-core
  panique au merge de schema).
- `crates/application` — use-cases `reconcile_*`, ports
  (`ForgejoGateway`, `SecretStore`, factories, `ReferenceReader`,
  `PolicySource`). La résolution des `*Ref` (`use_cases/refs`) et
  l'allow-list (`use_cases/admission`) y vivent ; l'import n'y produit que
  des noms + specs + objet Forgejo à posséder, jamais de CR.
- `crates/adapters-inbound` — un controller kube.rs par CRD + webhook axum.
  Aucune lecture cluster hors du CR réconcilié : tout passe par les ports.
- `crates/adapters-outbound` — `ForgejoHttpGateway` (wrap
  `forgejo-client`, un fichier par ressource, gestion du header `Sudo`),
  `K8sSecretStore`, `VaultSecretStore`, fan-out, `KubeClusterReader`.
- `crates/forgejo-client` — **client généré** (cf. ci-dessous), commité.
- `crates/operator` — binaire (wiring, leader election, TLS webhook, otel).
- `crates/crdgen` — génère `deploy/crd/*.yaml`.
- `crates/importer` — CLI `weebo-forgejo-importer` : lit un Forgejo réel
  (port `ForgejoInventory`), construit les CR (`manifests` : namespace,
  status amorcé, annotation de propriétaire des clés), émet leur YAML ou
  les crée avec `forgejoId` amorcé (chemin d'adoption).
- `crates/testkit` — envtest, mock wiremock, factories statiques.

### Client Forgejo généré

- Spec Swagger 2.0 vendorée : `spec/forgejo-v<version>.json`, extraite de
  `templates/swagger/v1_json.tmpl` au tag voulu (deux placeholders
  `{{AppVer}}` / `{{AppSubUrl}}` remplacés par `sed`).
- Correctifs de spec dans `spec/patches/*.jq`, appliqués avant génération.
- Générateur : **openapi-generator** (`rust`, bibliothèque `reqwest`),
  comme `authentik-client`. Java fourni par mise.
- `task gen:client [FORGEJO_VERSION=16.0.5]` : télécharge, patche,
  génère dans `crates/forgejo-client`. Branché dans `task recu` en mode
  hors-ligne (régénère depuis la spec vendorée) ; sortie commitée,
  vérifiée par le regen-and-diff de la CI.
- Pas de `forgejo-api` (crates.io) : on préfère rester au plus près de la
  spec source. Extraction en crate publié possible plus tard.

## Documentation

Site **Fumadocs** dans `docs/` comme authentik : pages CRD + JSON schemas
générés par `task recu` (jamais édités à la main), composant formulaire
→ YAML, guides rédigés : install, connecter une instance, premier
dépôt/org/équipe, utilisateurs OIDC (pré-provisionnés vs observés),
allow-list, migration (importer).

## Stratégie de tests

Quatre couches, comme authentik :
1. Unit domain / use-cases avec `FakeGateway`.
2. Contrat `ForgejoHttpGateway` contre `wiremock` (409, 422, Sudo, secrets
   uniques…).
3. Intégration controllers sous envtest (kube-apiserver + etcd réels,
   sans Docker).
4. E2E kind + Forgejo jetable, hebdomadaire. Plus les tests "live"
   (`#[ignore]`, `task test:live-forgejo`) : gateway HTTP réel puis tous les
   controllers sur envtest, contre un Forgejo réel (sidecar du devfile, ou
   conteneur local) — c'est cette couche qui a révélé les constats du M1.

**Couverture (M5)** : `task coverage` exécute toutes les couches sous
`cargo llvm-cov` — y compris les suites live (`--include-ignored`) contre un
Forgejo jetable (`task forgejo:container:start`, docker/podman, avec
source d'authentification OAuth2 pour les users externes) et les binaires
eux-mêmes (`operator` sur envtest : webhook TLS, lease, perte → exit 1 ;
`weebo-forgejo-importer` ; `crdgen`) — et échoue sous **85 % des
lignes**. Exclus : le client généré et les harnais de test. Job `coverage`
de la CI. Chaque fonctionnalité a son test bout en bout (controllers réels
+ envtest + Forgejo réel) : `live_forgejo.rs`, `live_identities.rs`,
`live_repositories.rs`, `live_credentials.rs` (dont Vault réel en
Kubernetes auth contre envtest), `instance_tls.rs` (CA / insecure).

Les tests de controllers (couche 3) utilisent le `FakeForgejo` en mémoire
(`application::test_support`, feature `test-support`) plutôt que wiremock :
le contrat HTTP est déjà couvert par la couche 2, et un faux à état permet
de tester renommages, membres et watches sans scripter chaque réponse.

## Outillage **(≠ authentik sur plusieurs points)**

- Includes Taskfile dans **`.tasks/`** (`.task/` = cache interne de Task).
- `task audit` : `cargo deny check` + `trivy` (fs + Containerfile).
- `Containerfile` + `Containerfile.hardened` multi-stage (référence
  batlehub), au lieu d'un unique `Dockerfile`.
- Devfile : sidecar Forgejo v16 en SQLite, `sleep infinity`, démarré et
  amorcé (admin + token) par `.tasks/forgejo.yaml`.
- CI GitHub Actions compatible Forgejo Actions : `ci` (lint, test,
  regen-and-diff, helm-lint, build image), `e2e` (cron), `release`
  (`cog bump --auto`), `publish` (tag `v*` → image + chart OCI ghcr).

## Jalons

| Jalon | Contenu |
|---|---|
| **M0** ✅ | Squelette workspace, Taskfile/`.tasks`, client généré + `gen:client`, sidecar devfile, Containerfiles, `task audit`, CI |
| **M1** ✅ | `ForgejoInstance`, `ForgejoUser` (3 modes), `ForgejoOrganization`, `ForgejoTeam` + envtest/wiremock + test live (`task test:live-forgejo`) |
| **M2** ✅ | `ForgejoRepository` (+ `teamRefs`), `ForgejoWebhook`, `ForgejoDeployKey`, `ForgejoUserKey` |
| **M3** ✅ | `ForgejoOAuth2Application` (Sudo), `ForgejoAccessToken`, Vault + fan-out des secrets |
| **M4** ✅ | `ForgejoNamespacePolicy` (+ `allowedUsers`) + webhook, chart Helm, Fumadocs |
| **M5** | `importer`, e2e kind, leader election testée, pipeline de release (premier bump : utilisateur) |
| **Plus tard** | Actions (secrets, variables, tokens runner) |
