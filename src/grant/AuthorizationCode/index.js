const ejs = require('ejs');
const path = require('path');
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
		async tokenHandler({ body, data, client, tokenCreated }) {
			const code = finalOptions.code.store.get(body.code);

			if (!code || code.client.id !== client.id || !code.redirectUri) {// 异常处理400
				throw new Error('Invalid grant: authorization code is invalid');
			}

			if (code.expiredAt < new Date()) {
				throw new Error('Invalid grant: authorization code has expired');
			}

			const redirectUri = body.redirect_uri;

			if (!urlReg.test(redirectUri) || redirectUri !== code.redirectUri) {
				throw new Error('Invalid request: `redirect_uri` is invalid');
			}

			if (!finalOptions.code.store.revoke(code.id)) {
				throw new Error('Invalid grant');
			}

			const user = code.user;

			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				throw new Error('Invalid grant: inavlid scope');
			}
			
			const token = tokenCreated(data);

			await finalOptions.saveToken(data, user, client);

			return token;
		},
		install({
			router
		}) {
			router({
				test(req, prefix) {
					const url = new URL(req.url, 'http://example');
					const approvePath = path.join(prefix, finalOptions.path.approve).toString().replace(/\\/g, '/');

					if (url.pathname === approvePath && req.method === 'GET') {
						return true;
					}

					return false;
				},
				async handler(req, res, oauth) {
					const user = finalOptions.userAuthenticate.getAuthenticatedUser(req);
					const query = new URL(req.url, 'http://example').searchParams;

					fs.readFile(finalOptions.userAuthenticate.approvePagePath, 'utf-8', (err, data) => {
						if (err) {
							return res.writeHead(500).end(JSON.stringify(err));
						}

						const authorizePath = url.format({
							pathname: path.join(oauth.prefix, finalOptions.path.authorize).toString().replace(/\\/g, '/'),
							query: {
								client_id: query.get('client_id'),
								client_secret: query.get('client_secret'),
								response_type: query.get('response_type'),
								redirect_uri: query.get('redirect_uri'),
								scope: query.get('scope'),
								state: query.get('state')
							}
						});
						res.end(ejs.render(data, {
							user,
							authorizePath
						}));
					});
				}
			});

			router({
				test(req, prefix) {
					const url = new URL(req.url, 'http://example');
					const authorizePath = path.join(prefix, finalOptions.path.authorize).toString().replace(/\\/g, '/');

					if (url.pathname === authorizePath) {
						return true;
					}

					return false;
				},
				async handler(req, res, oauth) {
					const query = new URL(req.url, 'http://example').searchParams;
					const clientId = query.get('client_id');
					const clientSecret = query.get('client_secret');
					const redirectUri = query.get('redirect_uri');
					const scope = query.get('scope') || finalOptions.scope.default;
					const responseType = query.get('response_type');
					const state = query.get('state');

					if (!clientId || !clientSecret) {
						throw new Error('Missing parameter: `client_id` or `client_secret`');
					}

					if (redirectUri && !urlReg.test(redirectUri)) {
						throw new Error('Invalid request: `redirect_uri` is not a valid URI');
					}

					const client = await oauth.getClient(clientId, clientSecret);

					if (!client) {
						throw new Error('Invalid client: client credentials are invalid');
					}

					if (!client.grants || client.grants.indexOf('authorization_code') < 0) {
						throw new Error('Invalid client: `grant_type` is invalid');
					}

					if (!client.redirectUris || 0 === client.redirectUris.length) {
						throw new Error('Invalid client: missing client `redirectUri`');
					}

					if (redirectUri && client.redirectUris.indexOf(redirectUri) < 0) {
						throw new Error('Invalid client: `redirect_uri` does not match client value');
					}

					if (req.method === 'GET') {
						const approvePath = url.format({
							pathname: path.join(oauth.prefix, finalOptions.path.approve),
							query: {
								client_id: clientId,
								client_secret: clientSecret,
								response_type: responseType,
								redirect_uri: redirectUri,
								scope,
								state
							}
						});

						res.writeHead(302, {
							Location: approvePath
						});
						res.end();
					}

					if (req.method === 'POST') {
						const user = oauth.body.user || finalOptions.userAuthenticate.getUserByCredentials(oauth.body.username, oauth.body.password);
						
						if (!user) {
							res.statusCode = 401;
							res.end();
						}

						const uri = query.get('redirect_uri') || client.redirectUris[0];
						const code = {
							id: finalOptions.code.Id(user, client, scope),
							expiredAt: Date.now() + finalOptions.code.lifetime,
							redirectUri,
							scope,
							client
						};

						await finalOptions.code.store.save(code, user, client);

						if (!finalOptions.allowEmptyState && !state) {
							throw new Error('Missing parameter: `state`');
						}

						res.writeHead(302, {
							Location: responseTypes[responseType]({
								codeId: code.id,
								state
							}).buildRedirectUri(uri)
						});
						res.end();
					}
				}
			});
		}
	};
};