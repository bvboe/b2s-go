# Web Frontend Development

This directory contains the static web frontend for bjorn2scan.

## Quick Start for Local Development

For rapid frontend iteration without rebuilding the backend:

### 1. Start Backend Port-Forward

```bash
# From project root
./scripts/port-forward

# OR manually:
kubectl port-forward svc/bjorn2scan 8080:80 -n <namespace>
```

### 2. Run Local Frontend Server

```bash
# From project root OR scripts folder
./scripts/run-local-frontend
```

### 3. Access Frontend

Open your browser to: **http://localhost:9000**

## How It Works

The `run-local-frontend` script:
- Runs nginx in a Docker container
- Mounts the `scanner-core/web/` directory for live HTML editing
- Proxies API calls (`/api/*`, `/health`, `/info`) to `localhost:8080` (your port-forwarded backend)
- Serves the frontend on `http://localhost:9000`

## Development Workflow

1. Start port-forward to your backend (once)
2. Run `./scripts/run-local-frontend` (once)
3. Edit HTML/CSS/JS files in `scanner-core/web/`
4. Refresh browser to see changes (no rebuild needed!)
5. Press Ctrl+C to stop the frontend server

## Files

- **index.html** - Main dashboard
- **images.html** - Images page with filtering/pagination
- **sql.html** - SQL debug console
- **dev-nginx.conf** - Nginx configuration for local development

## Production

In production, these HTML files are:
1. Embedded into the Go binary using `//go:embed`
2. Served directly by the k8s-scan-server or bjorn2scan-agent
3. No separate nginx needed

## Troubleshooting

**"Connection refused" errors:**
- Ensure backend port-forward is running on localhost:8080
- Check: `curl http://localhost:8080/health`

**"Cannot connect to the Docker daemon":**
- Ensure Docker Desktop is running

**Changes not appearing:**
- Hard refresh browser (Cmd+Shift+R on Mac, Ctrl+Shift+R on Windows/Linux)
- Files are mounted read-only, so changes should be instant
