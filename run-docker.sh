#!/bin/bash
docker run -it --rm -p 8000:8000 -v "$(pwd)/backend_app":/app/backend_app seal-save
