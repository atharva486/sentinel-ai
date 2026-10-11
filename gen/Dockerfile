FROM python:3.12-alpine

WORKDIR /app
COPY generate.py /app/
ENV PYTHONUNBUFFERED=1

# generate.py uses ONLY the standard library (argparse, asyncio, random, time),
# so there is nothing to pip install. (`pip install asyncio` was wrong: asyncio
# is part of the standard library, not a package.)
#
# Stay alive so `docker compose exec <service> python generate.py ...` can drive
# the SAME long-running container. That keeps each generator's IP stable, which
# is what makes labelling by source container work. Do NOT exit after --help.
CMD ["tail", "-f", "/dev/null"]
