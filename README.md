# Image Pack Webserver

Small Go service that pulls container images asynchronously, stores a cached tar archive on disk, and returns a download link when the archive is ready.

## Run

```sh
docker compose up --build
```

Request an image:

```sh
curl -X POST http://localhost:8080/api/images \
  -H 'Content-Type: application/json' \
  -d '{"image":"busybox:latest","platform":"linux/amd64"}'
```

Poll the returned `status_url` until `status` is `ready`, then download from `download_url`.

## API

- `GET /healthz`: health check.
- `POST /api/images`: create or reuse an image archive job.
- `GET /api/images?image=busybox:latest&platform=linux/amd64`: link-friendly request form.
- `GET /api/jobs/{id}`: inspect job status.
- `GET /api/downloads/{key}/{filename}`: download a ready archive.

Registry credentials can be passed in the JSON body:

```json
{
  "image": "registry.example.com/private/app:latest",
  "username": "registry-user",
  "password": "registry-password"
}
```

They can also be passed as headers:

- `X-Registry-Username`
- `X-Registry-Password`
- `X-Registry-Token`
- `X-Registry-Auth`

Credentials are not stored in job state. The cache key includes a credential fingerprint so anonymous and credentialed requests do not share the same artifact.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8080` | HTTP listen address. |
| `DATA_DIR` | `/data` | Cache and temporary archive directory. |
| `PUBLIC_BASE_URL` | empty | External base URL used in generated links behind a reverse proxy. |
| `BASIC_AUTH_USER` | empty | Enables endpoint basic auth when set with `BASIC_AUTH_PASSWORD`. |
| `BASIC_AUTH_PASSWORD` | empty | Basic auth password. |
| `CACHE_TTL` | `24h` | Time since last access before cached archives are removed. |
| `JOB_TTL` | `24h` | Time before completed in-memory job records are removed. |
| `CLEANUP_INTERVAL` | `15m` | Cleanup loop interval. |
| `REQUEST_TIMEOUT` | `45m` | Maximum pull and pack duration per job. |
| `MAX_CONCURRENT_DOWNLOADS` | `2` | Number of concurrent image pulls. |

When no `PUBLIC_BASE_URL` is configured, generated URLs use `X-Forwarded-Proto` and `X-Forwarded-Host` when present.
