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

const user = {
	get: async (ctx, app) => {
		const result = await ctx.pg.query('SELECT permission FROM users.permission WHERE name = (SELECT name FROM users.sessions WHERE hash = $1::text) AND app = $2::text;', [ctx.request.body.hash, app]);

		if(result.rowCount == 0) {
			throw 404;
		} else {
			ctx.body = result.rows[0].permission;
		}
	},
	login: async (ctx) => {
		try {
			const result = await ctx.pg.query('SELECT users.login($1::text, $2::text);', [ctx.request.body.name, ctx.request.body.pass]);

			ctx.body = {
				user: ctx.request.body.name,
				sessionid: result.rows[0].login
			};
		} catch(e) {
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
	logout: async (ctx, user) => {
		try {
			const result = await ctx.pg.query('DELETE FROM users.sessions_real WHERE userid = (SELECT id FROM users.users WHERE name = $1::text);', [user]);

			ctx.body = result.command + ' ' + result.rowCount;
		} catch(e) {
			throw e;
		}
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

app.use(route.post('/:app', user.get));
app.use(route.del('/:user', user.logout));
app.use(route.post('/', user.login));

app.listen(config.port);
