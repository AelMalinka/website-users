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
	app TEXT NOT NULL,
	data JSONB NOT NULL
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
		users.sessions_real.id, name, encode(digest(name || time, 'sha256'), 'base64') AS hash
	FROM
		users.sessions_real
	INNER JOIN
		users.users ON users.users.id = users.sessions_real.userid
	WHERE
		expire > now()
;

CREATE VIEW
	users.permission (name, app, permission)
AS
	SELECT
		users.users.name,
		users.permissions.app,
		json_agg(users.permissions.data)
	FROM
		users.permissions
	INNER JOIN
		users.users_x_permissions ON users.permissions.id = users.users_x_permissions.permission
	INNER JOIN
		users.users ON users.users_x_permissions.userid = users.users.id
	GROUP BY
		name, app
;

--- Functions

CREATE FUNCTION users.login(uname TEXT, pw TEXT) RETURNS TEXT AS $$
DECLARE
	valid BOOLEAN := false;
	ret TEXT := '';
	tid INT := 0;
BEGIN
	SELECT (pass = crypt(pw, pass)) INTO valid FROM users.users WHERE name = uname;
	IF NOT FOUND THEN
		RAISE foreign_key_violation USING message = 'user not found';
	END IF;
	IF valid THEN
		INSERT INTO users.sessions_real(userid) SELECT id FROM users.users WHERE name = uname RETURNING id INTO STRICT tid;
		SELECT hash INTO STRICT ret FROM users.sessions WHERE id = tid;
	ELSE
		RAISE check_violation USING message = 'invalid password';
	END IF;

	RETURN ret;
END;
$$ LANGUAGE plpgsql;

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
