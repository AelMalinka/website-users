---	Copyright 2017 (c) Michael Thomas (malinka) <malinka@entropy-development.com>
---	Distributed under the terms of the GNU Affero General Public License v3

DROP SCHEMA users CASCADE;

--- General

CREATE SCHEMA users;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

--- Tables

CREATE TABLE users.users (
	id SERIAL PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	pass TEXT NOT NULL
);

CREATE TABLE users.permissions (
	id SERIAL PRIMARY KEY,
	data JSON NOT NULL
);

CREATE TABLE users.users_x_permissions (
	userid INT REFERENCES users.users,
	permission INT REFERENCES users.permissions
);

CREATE TABLE users.sessions_real (
	id SERIAL PRIMARY KEY,
	userid INT REFERENCES users.users,
	time TIMESTAMP WITH TIME ZONE DEFAULT now(),
	expire TIMESTAMP WITH TIME ZONE DEFAULT now() + '10 minutes'
);

CREATE VIEW
	users.sessions (id, name, hash)
AS
	SELECT
		users.sessions_real.id, name, digest(name || time, 'sha512') AS hash
	FROM
		users.sessions_real
	INNER JOIN
		users.users ON users.users.id = users.sessions_real.userid
	WHERE
		expire > now()
;

--- Functions

CREATE FUNCTION users.login(uname TEXT, pw TEXT) RETURNS BYTEA AS $$
DECLARE
	valid BOOLEAN := false;
	ret TEXT := '';
	tid INT := 0;
BEGIN
	SELECT (pass = crypt(pw, pass)) INTO STRICT valid FROM users.users WHERE name = uname;
	IF valid THEN
		INSERT INTO users.sessions_real(userid) SELECT id FROM users.users WHERE name = uname RETURNING id INTO STRICT tid;
		SELECT hash INTO STRICT ret FROM users.sessions WHERE id = tid;
	END IF;

	RETURN ret;
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION users.logout(uname TEXT) RETURNS VOID AS $$
DELETE FROM users.sessions_real WHERE userid = (SELECT id FROM users.users WHERE name = uname);
$$ LANGUAGE SQL;

--- Triggers

CREATE FUNCTION users.sessions_update_trigger() RETURNS TRIGGER AS $$
BEGIN
	DELETE FROM users.sessions_real WHERE expire <= now();
	RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER insert_trigger
BEFORE INSERT ON users.sessions_real
EXECUTE PROCEDURE users.sessions_update_trigger();

CREATE TRIGGER update_trigger
BEFORE UPDATE ON users.sessions_real
EXECUTE PROCEDURE users.sessions_update_trigger();
