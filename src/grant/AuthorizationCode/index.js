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
		async createToken(res, { body, data, parsedClinet, getClient, extensible, tokenCreated }) {
			const code = finalOptions.code.store.get(body.code);
			const client = getClient(parsedClinet.clientId, null, true);

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

			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}
			
			const user = code.user;

			if (!user) {
				res.statusCode = 400;
				res.end('Invalid grant: user does not matched');
			}

			if (extensible) {
				const customAttributes = await finalOptions.token.extend(body);
				data.customAttributes = customAttributes;
			}
			
			const token = tokenCreated(data);

			await finalOptions.token.store.save(data, user, client);

			return token;
		},
		install({ router }) {
			router({
				path: finalOptions.path.approve,
				async handler(req, res) {
					const path = new URL(req.url, 'http://example')
					const user = finalOptions.userAuthenticate.getAuthenticatedUser(req);
					const prefix = path.pathname.substring(0, path.pathname.lastIndexOf('/'));
					const query = path.searchParams;

					fs.readFile(finalOptions.userAuthenticate.approvePagePath, 'utf-8', (err, data) => {
						if (err) {
							return res.writeHead(500).end(JSON.stringify(err));
						}

						res.end(ejs.render(data, {
							user,
							authorizePath: url.format({
								pathname: prefix + finalOptions.path.authorize,
								query: {
									client_id: query.get('client_id'),
									response_type: query.get('response_type'),
									redirect_uri: query.get('redirect_uri'),
									scope: query.get('scope'),
									state: query.get('state')
								}
							})
						}));
					});
				}
			});

			router({
				path: finalOptions.path.authorize,
				async handler(req, res, oauth) {
					const path = new URL(req.url, 'http://example')
					const query = path.searchParams;
					const clientId = query.get('client_id');
					const redirectUri = query.get('redirect_uri');
					const scope = query.get('scope') || finalOptions.scope.default;
					const responseType = query.get('response_type');
					const state = query.get('state');

					if (!clientId) {
						res.statusCode = 400;
						res.end('Invalid request: missing parameter: `client_id`');
					}

					const client = await oauth.getClient(clientId, null, true);

					if (!client) {
						res.statusCode = 400;
						res.end('Invalid client: client credentials are invalid');
					}

					if (!client.redirectUris || 0 === client.redirectUris.length) {
						res.statusCode = 400;
						res.end('Invalid client: missing parameter `redirectUri`');
					}

					if (redirectUri && !urlReg.test(redirectUri)) {
						res.statusCode = 400;
						res.end('Invalid request: `redirect_uri` is not a valid URI');
					}

					if (!client.grants || client.grants.indexOf('authorization_code') < 0) {
						res.statusCode = 400;
						res.end('Invalid client: `grant_type` is invalid');
					}

					if (redirectUri && client.redirectUris.indexOf(redirectUri) < 0) {
						res.statusCode = 400;
						res.end('Invalid client: `redirect_uri` does not match client value');
					}

					if (!finalOptions.scope.validate(finalOptions.scope.accept, scope, finalOptions.scope.valueValidate)) {
						res.statusCode = 400;
						res.end('Invalid scope: `scope` does not matched');
					}

					if (responseType !== 'code') {
						res.statusCode = 400;
						res.end('Unsupported response type: `code` does not supported');
					}

					if (req.method === 'GET') {
						const prefix = path.pathname.substring(0, path.pathname.lastIndexOf('/'));
						const approvePath = url.format({
							pathname: prefix + finalOptions.path.approve,
							query: {
								client_id: clientId,
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
							throw new Error('Invalid request: missing parameter `state`');
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