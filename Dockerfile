# Copyright 2017 (c) Michael Thomas (malinka) <malinka@entropy-development.com>
# Distributed under the terms of the GNU Affero General Public License v3

FROM aelmalinka/node

RUN mkdir -p /code
COPY . /code
WORKDIR /code
RUN npm install
VOLUME /code

ENV	PGHOST="localhost" \
	PGUSER="website" \
	PGDATABASE="website" \
	PGPORT="5432" \
	PGPASSWORD="" \
	PORT="8080"

CMD [ "npm", "start" ]
