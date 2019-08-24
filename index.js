const normalize = require('./src/normalize');
const { BearerToken } = require('./src/token/types');
const TokenModel = require('./src/token');
const utils = require('./src/utils');

function DefaultRequestBodyGetter(req) {
	return function getBody() {
		const chunks = [];

		return new Promise((resolve, reject) => {
			req
				.on('error', error => reject(error))
				.on('data', chunk => chunks.push(chunk))
				.on('end', () => {
					const length = chunks.reduce((length, chunk) => length += chunk.length, 0);
					const data = Buffer.concat(chunks, length).toString();
					const search = new URLSearchParams(data);
					const body = {};

					search.forEach((value, key) => body[key] = value);

					resolve(body);
				});
		});
	};
}

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
			getBody = DefaultRequestBodyGetter(req),
		} = injection;

		if (url.pathname === finalOptions.token.path && req.method === 'POST') {
			if (req.headers['content-type'] === 'application/x-www-form-urlencoded') {
				const body = await getBody();
				const payload = {
					body,
					query: url.searchParams,
					headers: req.headers
				};

				try {
					for (const typeName in finalOptions.grantTypes) {
						const grantType = finalOptions.grantTypes[typeName];

						if (body.grant_type !== grantType.type) {
							continue;
						}
						
						const credentials = utils.authorizationParser(payload);
						const client = finalOptions.client.get(credentials.clientId, credentials.clientSecret);
						const oauth = {
							client,
							body,
							getCredentials() {
								return {
									username: body.username,
									password: body.password
								};
							}
						};
						const user = await grantType.queryUser(oauth);
						const data = {
							accessToken: {
								id: finalOptions.token.Id.Access(),
								expiredAt: Date.now() + finalOptions.token.lifetime.access
							},
							refreshToken: (grantType.refreshable && finalOptions.token.refreshable) ? {
								id: finalOptions.token.Id.Refresh(),
								expiredAt: Date.now() + finalOptions.token.lifetime.refresh
							} : null,
							scope: finalOptions.scope.validate(user, client, body.scope),
							user, 
							client
						};

						await finalOptions.token.save(data, user, client);

						const token = BearerToken(TokenModel(data, {
							extensible: finalOptions.token.extensible
						}));

						res.statusCode = 200;
						res.setHeader['Cache-Control'] = 'no-store';
						res.setHeader['Pragma'] = 'no-cache';
						res.end(JSON.stringify(token.valueOf()));
						break;
					}
				} catch (error) {
					res.statusCode = 500;
					res.end(JSON.stringify(error.message));
				}
			} else {
				res.statusCode = 400;
				res.end('Bad request.');
			}

			return true;
		}

		const matchedRouter = routers.find(router => router.test(req));

		if (matchedRouter) {
			await matchedRouter.handler(req, res, {
				body: await getBody(),
				getClient(id, secret) {
					return finalOptions.client.get(id, secret);
				}
			});

			return true;
		}

		return false;
	};
};

OAuth.AuthorizationCode = require('./src/grant/AuthorizationCode');
OAuth.PasswordCredentials = require('./src/grant/PasswordCredentials');
OAuth.ClientCredentials = require('./src/grant/ClientCredentials');