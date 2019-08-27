const normalize = require('./src/normalize');
const path = require('path');
const utils = require('./src/utils');

const OAuth = module.exports = function OAuthHandler(options) {
	const finalOptions = normalize(options);
	const routers = [];

	finalOptions.grantTypes.forEach(type => {
		if (type.install) {
			type.install({
				router(options) {
					routers.push(options);
				}
			});
		}
	});

	return async function (req, res, injection = {}) {
		const url = new URL(req.url, 'http://example');
		const {
			getBody = utils.getBody(req),
		} = injection;
		const tokenPath = path.join(finalOptions.prefix, finalOptions.token.path).toString().replace(/\\/g, '/');

		if (url.pathname === tokenPath && req.method === 'POST') {
			if (req.headers['content-type'] === 'application/x-www-form-urlencoded') {
				const body = await getBody();
				const payload = {
					body,
					query: url.searchParams,
					headers: req.headers
				};

				const grantType = finalOptions.grantTypes.find(grantType => {
					return grantType.type === body.grant_type;
				});

				if (grantType === 'undefined') {
					res.statusCode = 400;
					res.end('Bad request');
				}

				try {
					const checked = utils.authorizationParser(payload);
					const client = grantType.type === 'authorization_code' ? {
						id: checked.clientId
					} : finalOptions.client.get(checked.clientId, checked.clientSecret);

					if (!client) {
						res.statusCode = 400;
						res.end('Bad request');
					}

					const scope = body.scope;
					const data = {
						accessToken: {
							id: finalOptions.token.Id.Access(),
							expiredAt: Date.now() + finalOptions.token.lifetime.access
						}
					};

					if (!scope) {
						data.scope = finalOptions.scope.default;
					} else if (finalOptions.scope.validate(finalOptions.scope.accept, scope, finalOptions.scope.valueValidate)) {
						data.scope = body.scope;
					}

					if (grantType.refreshable && finalOptions.token.refreshable) {
						data.refreshToken = {
							id: finalOptions.token.Id.Refresh(),
							expiredAt: Date.now() + finalOptions.token.lifetime.refresh
						};
					}

					if (finalOptions.token.extensible) {
						const customAttributes = await finalOptions.token.extend(body);

						data.customAttributes = customAttributes;
					}

					await finalOptions.token.save(data, grantType.type);

					const token = await grantType.tokenHandler({
						body,
						data: Object.assign({}, data),
						client,
						tokenCreated: finalOptions.token.created,
						tokenRefreshed: finalOptions.token.refreshed
					});

					res.statusCode = 200;
					res.setHeader['Cache-Control'] = 'no-store';
					res.setHeader['Pragma'] = 'no-cache';
					res.end(JSON.stringify(token));
				} catch (error) {
					res.statusCode = 500;
					res.end(JSON.stringify(error.message));
				}
			} else {
				res.statusCode = 400;
				res.end('Bad request.');
			}
		}

		const matchedRouter = routers.find(router => router.test(req, finalOptions.prefix));

		if (matchedRouter) {
			await matchedRouter.handler(req, res, {
				body: await getBody(),
				getClient(id, secret, isAuthorize = false) {
					return finalOptions.client.get(id, secret, isAuthorize);
				},
				prefix: finalOptions.prefix
			});
		}
	};
};

OAuth.AuthorizationCode = require('./src/grant/AuthorizationCode');
OAuth.PasswordCredentials = require('./src/grant/PasswordCredentials');
OAuth.ClientCredentials = require('./src/grant/ClientCredentials');
OAuth.RefershToken = require('./src/grant/RefreshToken');