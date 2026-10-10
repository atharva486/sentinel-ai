# Proxy image = nginx + tcpdump.
# The capture step (`docker compose exec proxy tcpdump ...`) needs tcpdump, but
# the stock nginx:alpine image does not ship it. Baking it in means capture keeps
# working after every `docker compose up --build` / container recreation, instead
# of silently breaking the moment the container is rebuilt.
FROM nginx:1.25-alpine

RUN apk add --no-cache tcpdump
