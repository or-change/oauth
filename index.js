const normalize = require('./src/normalize');
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
		const prefix = finalOptions.prefix;
		const url = new URL(req.url, 'http://example');
		const { getBody = utils.getBody(req) } = injection;
		const tokenPath = prefix + finalOptions.token.path;

		if (url.pathname === tokenPath && req.method === 'POST') {
			if ((req.headers['content-type'] !== 'application/x-www-form-urlencoded')) {
				res.statusCode = 400;
				res.end('Invalid request');
			}

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
				const parsedClient = utils.authorizationParser(payload);
				const scope = body.scope || finalOptions.scope.default;
				const data = {
					accessToken: {
						id: finalOptions.token.Id.Access(),
						expiredAt: Date.now() + finalOptions.token.lifetime.access
					}
				};

				if (finalOptions.scope.validate(finalOptions.scope.accept, scope, finalOptions.scope.valueValidate)) {
					data.scope = scope;
				}

				if (grantType.refreshable && finalOptions.token.refreshable) {
					data.refreshToken = {
						id: finalOptions.token.Id.Refresh(),
						expiredAt: Date.now() + finalOptions.token.lifetime.refresh
					};
				}

				const token = await grantType.createToken(res, {
					body,
					parsedClient,
					data: Object.assign({}, data),
					getClient(id, secret, isAuthorize = false) {
						return finalOptions.client.get(id, secret, isAuthorize);
					},
					extensible: finalOptions.token.extensible,
					tokenCreated: finalOptions.token.created,
					tokenRefreshed: finalOptions.token.refreshed
				});

				if (finalOptions.token.extensible) {
					Object.keys(token).forEach(key => {
						if (!data[key]) {
							data[key] = token[key];
						}
					});
				}

				await finalOptions.token.save(data, grantType.type);

				res.statusCode = 200;
				res.setHeader['Cache-Control'] = 'no-store';
				res.setHeader['Pragma'] = 'no-cache';
				res.end(JSON.stringify(token));
			} catch (error) {
				res.statusCode = 400;
				res.end(JSON.stringify(error.message));
			}
		}

		const matchedRouter = routers.find(router => {
			const routerPath = prefix + router.path;

			return url.pathname === routerPath;
		});

		if (matchedRouter) {
			await matchedRouter.handler(req, res, {
				body: await getBody(),
				getClient(id, secret, isAuthorize = false) {
					return finalOptions.client.get(id, secret, isAuthorize);
				}
			});
		}
	};
};

OAuth.AuthorizationCode = require('./src/grant/AuthorizationCode');
OAuth.PasswordCredentials = require('./src/grant/PasswordCredentials');
OAuth.ClientCredentials = require('./src/grant/ClientCredentials');
OAuth.RefershToken = require('./src/grant/RefreshToken');