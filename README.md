# Phoenix Core

Slice 0 executable bootstrap. No product capability is implemented.

## Run

```bash
PHOENIX_ENV=local npm run check
PHOENIX_ENV=local npm test
PHOENIX_ENV=local npm start
```

Health: `http://127.0.0.1:3000/health`
Readiness: `http://127.0.0.1:3000/ready`

## Container

```bash
docker build -t phoenix-core:3.0.0 .
docker run --rm -p 3000:3000 phoenix-core:3.0.0
```

The backend stack remains provisional until the decision preceding Identity Slice 1.
