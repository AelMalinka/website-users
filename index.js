/*	Copyright 2017 (c) Michael Thomas (malinka) <malinka@entropy-development.com>
	Distributed under the terms of the GNU Affero General Public License v3
*/

'use strict';

const koa = require('koa');

const logger = require('koa-logger');
const etag = require('koa-etag');
const conditional = require('koa-conditional-get');
const route = require('koa-route');
const body = require('koa-body');
const { Pool } = require('pg');

const config = require('./config.js');

const app = new koa();

const perm = {
	get: async (ctx, app) => {
		const result = await ctx.pg.query('SELECT permission FROM users.permission WHERE name = (SELECT name FROM users.sessions WHERE hash = $1::text) AND app = $2::text;', [ctx.session, app]);

		if(result.rowCount == 1) {
			ctx.body = result.rows[0].permission;
		} else if(result.rowCount == 0) {
			ctx.throw(404);
		} else {
			ctx.throw(500);
		}
	},
};
const user = {
	register: async (ctx) => {
		const result = await ctx.pg.query('INSERT INTO users.users (name, pass) VALUES ($1::text, crypt($2::text, gen_salt($3::text)));', [ctx.request.body.name, ctx.request.body.pass, config.cipher]);

		if(result.rowCount == 1) {
			await user.login(ctx);
		} else {
			ctx.throw(400);
		}
	},
	login: async (ctx) => {
		try {
			const result = await ctx.pg.query('SELECT users.login($1::text, $2::text);', [ctx.request.body.name, ctx.request.body.pass]);

			const sessionid = result.rows[0].login;

			ctx.cookies.set('session', sessionid);
			ctx.body = sessionid;
		} catch(e) {
			console.log(e);

			if(e.code == 23503) {
				e.status = 404;
				e.expose = true;
			} else if(e.code == 23514) {
				e.status = 401;
				e.expose = true;
			}

			throw e;
		}
	},
	logout: async (ctx) => {
		const result = await ctx.pg.query('DELETE FROM users.sessions_real WHERE username = (SELECT name FROM users.sessions WHERE hash = $1::text);', [ctx.session]);

		ctx.body = result.command + ' ' + result.rowCount;
	},
};

app.use(logger());
app.use(body());
app.use(etag());
app.use(conditional());

app.use(async (ctx, next) => {
	ctx.pg = new Pool();

	await next();
});

app.use(async (ctx, next) => {
	ctx.session = ctx.cookies.get('session');

	console.log(ctx.session);

	await next();
});

app.use(route.post('/register', user.register));
app.use(route.post('/login', user.login));
app.use(route.get('/logout', user.logout));

app.use(route.get('/perm/:app', perm.get));

app.listen(config.port);
