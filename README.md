# CT Listener

Service qui écoute le flux Certificate Transparency (CertStream) en continu, filtre les nouveaux NDD par TLD et les expose via une API HTTP.

## API

| Endpoint | Description |
|---|---|
| `GET /health` | Ping (public) |
| `GET /stats` | Statistiques et TLDs surveillés |
| `GET /recent?n=50` | 50 derniers domaines captés |
| `GET /today?tld=.be&format=json` | NDD du jour (plain txt par défaut) |
| `GET /date/2026-04-23?tld=.fr` | NDD d'une date donnée |
| `GET /days` | Liste des jours disponibles avec leur count |

## Variables d'environnement

- `TLDS` : liste de TLDs surveillés, séparés par virgule. Défaut : `.fr,.be,.ch,.eu,.de,.nl,.es,.it,.uk,.com,.net,.org,.io,.shop,.online,.xyz`
- `ACCESS_TOKEN` : optionnel, si défini toutes les routes sauf `/health` demandent `?token=...` ou header `Authorization: Bearer ...`
- `RETENTION_DAYS` : rétention des fichiers en jours (défaut 30)
- `DATA_DIR` : défaut `/data` (volume Railway)
