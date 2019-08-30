const ejs = require('ejs');
const url = require('url');
const fs = require('fs');
const TYPE = 'authorization_code';
const urlReg = /^[a-zA-Z][a-zA-Z0-9+.-]+:/;
const responseTypes = {
	code: require('./responseTypes').Code,
	token: require('./responseTypes').Token
};
const normalize = require('./normalize');

module.exports = function AuthorizationCode(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async createToken({ res, body, clientQuery, token }) {
			const code = await finalOptions.code.store.get(body.code);
			const client = await token.queryClient(clientQuery.id, null, true);

			if (!client) {
				res.statusCode = 400;
				res.end('Invalid client: client does not matched');
			}
			
			if (!code || code.client.id !== client.id || !code.redirectUri) {
				res.statusCode = 400;
				res.end('Invalid grant: authorization code is invalid');
			}

			if (code.expiredAt < new Date()) {
				res.statusCode = 400;
				res.end('Invalid grant: authorization code has expired');
			}

			const redirectUri = body.redirect_uri;

			if (!urlReg.test(redirectUri) || redirectUri !== code.redirectUri) {
				res.statusCode = 400;
				res.end('Invalid request: `redirect_uri` is invalid');
			}

			if (!finalOptions.code.store.revoke(code.id)) {
				res.statusCode = 400;
				res.end('Invalid grant');
			}

			if (!finalOptions.scope.validate(finalOptions.scope.accept, token.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}
			
			const user = code.user;

			if (!user) {
				res.statusCode = 400;
				res.end('Invalid grant: user does not matched');
			}

			const extension = finalOptions.token.set(finalOptions.token.extensibleAttributes, body);

			if (extension) {
				token.extends(extension);
			}

			await finalOptions.token.store.save({
				accessToken: token.accessToken,
				refreshToken: token.refreshToken,
				scope: token.scope,
				extension
			}, user, client);


		},
		install({ router }) {
			router.get(finalOptions.path.approve, async ctx => {
				const path = new URL(ctx.req.url, 'http://example');
				const user = finalOptions.userAuthenticate.getAuthenticatedUser(ctx.req);
				const prefix = path.pathname.substring(0, path.pathname.lastIndexOf('/'));

				fs.readFile(finalOptions.userAuthenticate.approvePagePath, 'utf-8', (err, data) => {
					if (err) {
						return ctx.res.writeHead(500).end(JSON.stringify(err));
					}

					ctx.res.end(ejs.render(data, {
						user,
						authorizePath: url.format({
							pathname: prefix + finalOptions.path.authorize,
							query: ctx.query
						})
					}));
				});
			});

			router.get(finalOptions.path.authorize, async ctx => {
				const path = new URL(ctx.req.url, 'http://example');
				const {
					client_id: clientId,
					redirect_uri: redirectUri,
					response_type: responseType,
				} = ctx.query;

				if (!clientId) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid request: missing parameter: `client_id`');
				}

				if (redirectUri && !urlReg.test(redirectUri)) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid request: `redirect_uri` is not a valid URI');
				}

				if (!responseType) {
					ctx.res.statusCode = 400;
					ctx.res.end('Unsupported response type: `code` does not supported');
				}

				const prefix = path.pathname.substring(0, path.pathname.lastIndexOf('/'));
				const approvePath = url.format({
					pathname: prefix + finalOptions.path.approve,
					query: ctx.query
				});

				ctx.res.writeHead(302, {
					Location: approvePath
				});
				ctx.res.end();
			});

			
			router.post(finalOptions.path.authorize, async ctx => {
				const {
					client_id: clientId,
					redirect_uri: redirectUri,
					scope,
					response_type: responseType,
					state
				} = ctx.query;

				if (!clientId) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid request: missing parameter: `client_id`');
				}

				const client = await ctx.queryClient(clientId, null, true);

				if (!client) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid client: client credentials are invalid');
				}

				if (!client.redirectUris || 0 === client.redirectUris.length) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid client: missing parameter `redirectUri`');
				}

				if (redirectUri && !urlReg.test(redirectUri)) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid request: `redirect_uri` is not a valid URI');
				}

				if (!client.grants || client.grants.indexOf('authorization_code') < 0) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid client: `grant_type` is invalid');
				}

				if (redirectUri && client.redirectUris.indexOf(redirectUri) < 0) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid client: `redirect_uri` does not match client value');
				}

				if (!finalOptions.scope.validate(finalOptions.scope.accept, scope, finalOptions.scope.valueValidate)) {
					ctx.res.statusCode = 400;
					ctx.res.end('Invalid scope: `scope` does not matched');
				}

				if (responseType !== 'code') {
					ctx.res.statusCode = 400;
					ctx.res.end('Unsupported response type: `code` does not supported');
				}

				const user = ctx.request.body.user || finalOptions.userAuthenticate.getUserByCredentials(ctx.request.body.username, ctx.request.body.password);
				
				if (!user) {
					ctx.res.statusCode = 401;
					ctx.res.end();
				}

				const uri = redirectUri || client.redirectUris[0];
				const code = {
					id: finalOptions.code.Id(user, client, scope),
					expiredAt: Date.now() + finalOptions.code.lifetime,
					redirectUri,
					scope,
					client
				};

				await finalOptions.code.store.save(code, user, client);

				if (!finalOptions.allowEmptyState && !state) {
					throw new Error('Invalid request: missing parameter `state`');
				}

				ctx.res.writeHead(302, {
					Location: responseTypes[responseType]({
						codeId: code.id,
						state
					}).buildRedirectUri(uri)
				});
				ctx.res.end();

			});
		}
	};
};