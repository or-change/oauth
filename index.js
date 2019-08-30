'use strict';

const normalize = require('./src/normalize');
const utils = require('./src/utils');
const Router = require('./src/router');

const TOKEN_FIELD_KEYWORD = [
	'access_token',
	'refresh_token',
	'scope',
	'state',
	'token_type',
	'expires_in',
];

const OAuth = module.exports = function OAuthHandler(options) {
	const finalOptions = normalize(options);
	const router = Router(finalOptions.prefix, finalOptions.client.get);

	router.post(finalOptions.token.path, async ctx => {
		const requestBody = ctx.request.body;

		if ((ctx.req.headers['content-type'] !== 'application/x-www-form-urlencoded')) {
			ctx.res.statusCode = 400;
			ctx.res.end('Invalid request');
		}

		const grantType = finalOptions.grantTypes.find(grantType => {
			return grantType.type === requestBody.grant_type;
		});

		if (!grantType) {
			ctx.res.statusCode = 400;
			ctx.res.end('Bad request');
		}

		const clientQuery = utils.ClientQuery({
			query: ctx.query,
			headers: ctx.req.headers,
			body: requestBody
		});

		if (finalOptions.client.secret && !clientQuery.secret) {
			ctx.res.statusCode = 400;
			ctx.res.end('Invalid client query.');
		}

		const token = {
			accessToken: Object.freeze({
				id: finalOptions.token.Id.Access(),
				expiredAt: Date.now() + finalOptions.token.lifetime.access
			}),
			scope: finalOptions.scope.set(finalOptions.scope.accept,requestBody.scope, finalOptions.scope.valueValidate),
			extension: {}
		};

		if (!token.scope) {
			ctx.res.statusCode = 400;
			ctx.res.end('Invalid request: validate scope failed');
		}

		if (grantType.setScope) {
			token.scope = grantType.setScope(requestBody.scope);
		}

		if (grantType.refreshable && finalOptions.token.refreshable) {
			token.refreshToken = Object.freeze({
				id: finalOptions.token.Id.Refresh(),
				expiredAt: Date.now() + finalOptions.token.lifetime.refresh
			});
		}

		await grantType.createToken({
			res: ctx.res,
			body: requestBody,
			clientQuery,
			token: {
				get accessToken() {
					return token.accessToken;
				},
				get refreshToken() {
					return token.refreshToken;
				},
				get scope() {
					return token.scope;
				},
				queryClient(id, secret, isAuthorize = false) {
					return finalOptions.client.get(id, secret, isAuthorize);
				},
				extends(extensionObject) {
					if (!finalOptions.token.extensible) {
						throw new Error('The options is set to token extending NOT be allowed.');
					}

					const matchedKeyword = TOKEN_FIELD_KEYWORD.find(keyName => {
						return Object.prototype.hasOwnProperty.call(extensionObject, keyName);
					});

					if (matchedKeyword) {
						throw new Error(`The keyword field name '${matchedKeyword}' is found in extensionObject.`);
					}

					token.extension = extensionObject;
				},
				refreshed(refreshTokenId) {
					if (!finalOptions.token.refreshable) {
						throw new Error('The options is set to token refreshed NOT be allowed.');
					}

					return finalOptions.token.refreshed(refreshTokenId);
				}
			}
		});

		await finalOptions.token.save(token, grantType.type);

		ctx.res.statusCode = 200;
		ctx.res.setHeader['Cache-Control'] = 'no-store';
		ctx.res.setHeader['Pragma'] = 'no-cache';

		const tokenResponseBody = JSON.stringify(Object.assign({
			token_type: 'Bearer',
			access_token: token.accessToken.id,
			expires_in: finalOptions.token.lifetime.access,
			refresh_token: token.refreshToken && token.refreshToken.id
		}, token.extension));

		ctx.res.end(tokenResponseBody);
	});

	finalOptions.grantTypes.forEach(grantType => {
		if (grantType.install) {
			grantType.install({ router });
		}
	});

	return router.callback();
};

OAuth.AuthorizationCode = require('./src/grant/AuthorizationCode');
OAuth.PasswordCredentials = require('./src/grant/PasswordCredentials');
OAuth.ClientCredentials = require('./src/grant/ClientCredentials');
OAuth.RefershToken = require('./src/grant/RefreshToken');