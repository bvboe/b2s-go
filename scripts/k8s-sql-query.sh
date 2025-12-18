#!/bin/bash
#
# k8s-sql-query.sh - Run SQL queries on bjorn2scan scan-server database in Kubernetes
#
# Usage:
#   ./k8s-sql-query.sh "SELECT * FROM images LIMIT 10;"
#   ./k8s-sql-query.sh "SELECT * FROM images;" -n my-namespace
#   ./k8s-sql-query.sh "SELECT COUNT(*) FROM images;" --namespace=default
#

set -e

# Default namespace
NAMESPACE="default"

# Parse arguments
SQL_QUERY=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--namespace)
            NAMESPACE="$2"
            shift 2
            ;;
        --namespace=*)
            NAMESPACE="${1#*=}"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 \"SQL_QUERY\" [-n|--namespace NAMESPACE]"
            echo ""
            echo "Run SQL queries on the bjorn2scan scan-server SQLite database."
            echo ""
            echo "Options:"
            echo "  -n, --namespace    Kubernetes namespace (default: default)"
            echo "  -h, --help         Show this help message"
            echo ""
            echo "Examples:"
            echo "  $0 \"SELECT * FROM images LIMIT 10;\""
            echo "  $0 \"SELECT COUNT(*) FROM instances;\" -n production"
            echo "  $0 \"PRAGMA table_info(images);\" --namespace=default"
            exit 0
            ;;
        *)
            if [ -z "$SQL_QUERY" ]; then
                SQL_QUERY="$1"
            else
                echo "Error: Unexpected argument: $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if SQL query was provided
if [ -z "$SQL_QUERY" ]; then
    echo "Error: SQL query is required"
    echo "Usage: $0 \"SQL_QUERY\" [-n|--namespace NAMESPACE]"
    echo "Run '$0 --help' for more information"
    exit 1
fi

# Find the scan-server pod
echo "→ Finding scan-server pod in namespace '$NAMESPACE'..." >&2
POD_NAME=$(kubectl get pods \
    -l app.kubernetes.io/name=bjorn2scan,app.kubernetes.io/component=scan-server \
    -n "$NAMESPACE" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)

if [ -z "$POD_NAME" ]; then
    echo "Error: No scan-server pod found in namespace '$NAMESPACE'" >&2
    echo "Check that bjorn2scan is deployed and the namespace is correct" >&2
    exit 1
fi

echo "→ Running query on pod '$POD_NAME'..." >&2
echo "" >&2

# Run the SQL query
kubectl exec -i "$POD_NAME" -n "$NAMESPACE" -- sh -c "
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo '→ Installing sqlite3...' >&2
        apk add --quiet sqlite >/dev/null 2>&1
    fi
    sqlite3 /var/lib/bjorn2scan/containers.db \"$SQL_QUERY\"
"

echo "" >&2
echo "✓ Query complete" >&2
