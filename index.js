/*	Copyright 2017 (c) Michael Thomas (malinka) <malinka@entropy-development.com>
	Distributed under the terms of the GNU Affero General Public License v3
*/

'use strict';

const koa = require('koa');
const logger = require('koa-logger');
const route = require('koa-route');
const { Pool } = require('pg');

const config = require('./config.js');

const app = new koa();

app.use(logger());

app.use(async (ctx, next) => {
	ctx.pg = new Pool();

	await next();
});

app.listen(config.port);
