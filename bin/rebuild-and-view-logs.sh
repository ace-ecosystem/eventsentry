#!/usr/bin/env bash
cd /opt/eventsentry && docker-compose stop -t 1 && docker-compose build && docker-compose up -d && docker logs -f eventsentry_python_1
