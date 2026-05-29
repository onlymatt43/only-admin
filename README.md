# only-admin

Service admin central pour la gestion du catalogue media (videos, photos, liens), avec API admin, lecture service-to-service, et assistants utilitaires.

## Role dans l'ecosysteme

- source operationnelle du catalogue et des metadonnees
- expose un endpoint de lecture securise pour les consommateurs
- notifie les fronts consommateurs via webhooks de revalidation
- ne porte pas la logique produit/paiement (externalisee dans un hub dedie)

## Endpoints

### Admin API

Route: `GET/POST /api/admin-api?action=...`
Auth: `Authorization: Bearer ADMIN_TOKEN`

Actions actives:
- `list`
- `env-health`
- `update`
- `delete`
- `tag-boxes`
- `save-tag-box`
- `delete-tag-box`
- `import-link`
- `upload`
- `sync-videos`
- `quality-summary`
- `analytics`
- `resolve-duplicate`

Note:
- `action=by-destination` est retire de cette route et renvoie `410`.
- utiliser `GET /api/consumer-read?dest=...` pour la lecture service-to-service.

### Consumer Read (service-to-service)

Route: `GET /api/consumer-read?dest={destination}`
Auth: `Authorization: Bearer ADMIN_SERVICE_KEY`

Retourne les items `published` filtres par destination (`route:{dest}` / `destinations`) et signe les assets prives si necessaire.

### Admin Coach

- `POST /api/admin-coach`
- `POST /api/chat` (alias vers le meme handler)

Supporte les taches `metadata-suggest` et `admin-assist`.

### Image Proxy

- `GET /api/image-proxy?url=...`

Proxy image avec garde-fous SSRF (blocage localhost/reseaux prives, protocoles limites a HTTP/HTTPS).

## Variables d'environnement

### Core (requis)

- `ADMIN_TOKEN`
- `TURSO_DB_URL` (alias accepte: `TURSO_DATABASE_URL`)
- `TURSO_DB_TOKEN` (alias accepte: `TURSO_AUTH_TOKEN`)

### Lecture service-to-service

- `ADMIN_SERVICE_KEY` (alias accepte: `CHAUD_DEVANT_SERVICE_KEY`)

### Bunny media

- Public:
  - `BUNNY_PUBLIC_LIBRARY_ID` (alias: `BUNNY_LIBRARY_ID`)
  - `BUNNY_PUBLIC_LIBRARY_API_KEY` (alias: `BUNNY_ACCESS_KEY`)
  - `BUNNY_PUBLIC_PULL_ZONE_URL` (alias: `BUNNY_PULL_ZONE`)
- Prive:
  - `BUNNY_PRIVATE_LIBRARY_ID`
  - `BUNNY_PRIVATE_LIBRARY_API_KEY` (aliases: `BUNNY_PRIVATE_ACCESS_KEY`, `BUNNY_API_KEY`)
  - `BUNNY_PRIVATE_PULL_ZONE_URL` (aliases: `BUNNY_PRIVATE_PULL_ZONE`, `BUNNY_PULL_ZONE_HOST`)
  - `BUNNY_CDN_SIGNING_KEY` (aliases: `BUNNY_TOKEN_KEY`, `BUNNY_SIGNING_KEY`)
- Storage:
  - `BUNNY_STORAGE_NAME`
  - `BUNNY_STORAGE_API_KEY` (alias: `BUNNY_STORAGE_PASSWORD`)
  - `BUNNY_STORAGE_PULL_ZONE_URL` (alias: `BUNNY_STORAGE_PULL_ZONE`)

### Webhooks de notification

- `PROJECT_ROUTES_URL`
- `WEBHOOK_SECRET_PROJECT_LINKS` (aliases: `PROJECT_LINKS_REVALIDATE_SECRET`, `PROJECT_ROUTES_REVALIDATE_SECRET`)
- `CATALOG_SYNC_URL`
- `WEBHOOK_SECRET_SUPER_VIDEOTHEQUE` (aliases: `SUPER_VIDEOTHEQUE_WEBHOOK_SECRET`, `CATALOG_SYNC_WEBHOOK_SECRET`)

### Strict mode

- `ENV_STRICT_MODE=true|false`

Quand active, les actions admin (sauf `env-health`) peuvent etre bloquees si des variables critiques manquent.

## Developpement

```bash
npm install
npm run lint
npm run test
```

## Verification rapide

- Sante env: `GET /api/admin-api?action=env-health`
- Lecture destination: `GET /api/consumer-read?dest=super-videotheque` avec bearer `ADMIN_SERVICE_KEY`

## Notes

- Cette base est orientee API/serverless. L'UI admin locale est minimaliste (`index.html`) et consomme l'API.
- Les alias d'env legacy restent supportes temporairement, mais a migrer vers les noms canoniques.
