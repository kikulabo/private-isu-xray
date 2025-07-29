#!/bin/bash

# X-Ray SDK configuration
export AWS_XRAY_CONTEXT_MISSING=LOG_ERROR
export AWS_XRAY_LOG_LEVEL=info
export AWS_XRAY_TRACING_NAME=private-isu

# Enable detailed SQL query tracing
export AWS_XRAY_TRACE_SQL_QUERIES=true

# Start the application with gunicorn
exec /home/webapp/.venv/bin/gunicorn app:app \
    -b 0.0.0.0:8080 \
    --log-file - \
    --access-logfile - \
    --workers 2 \
    --threads 4 \
    --timeout 120
