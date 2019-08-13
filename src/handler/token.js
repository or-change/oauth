const TokenModel = require('../token');
const auth = require('basic-auth');
const { BearerToken } = require('../token/types');

const grantTypes = {
	authorization_code: require('../grant/authorizationCode'),
	client_credentials: require('../grant/clientCredentials'),
	password: require('../grant/passwordCredentials')
};

module.exports = function TokenHandler(options) {
	const {
		model,
		accessTokenLifeTime,
		refreshTokenLifeTime,
		allowExtendedTokenAttributes,
		requireClientAuthentication,
		alwaysIssueNewRefreshToken = false
	} = options;

	if (!accessTokenLifeTime) {
		throw new Error('Missing parameter: `accessTokenLifeTime`');
	}

	if (!refreshTokenLifeTime) {
		throw new Error('Missing parameter: `refreshTokenLifetime`');
	}

	if (!model) {
		throw new Error('Missing parameter: `model`');
	}

	if (!model.getClient) {
		throw new Error('Invalid argument: model does not implement `getClient()`');
	}

	function getClient(request) {
		const credentials = getClientCredentials(request);
		const grantType = request.body.grant_type;

		if (!credentials.clientId) {
			throw new Error('Missing parameter: `client_id`');
		}

		if (isClientAuthenticationRequired(grantType) && !credentials.clientSecret) {
			throw new Error('Missing parameter: `client_secret`');
		}

		const client = model.getClient(credentials.clientId, credentials.clientSecret);

		if (!client || !client.grants || !(client.grants instanceof Array)) {
			throw new Error('Invalid client.');
		}

		return client;
	}

	function getClientCredentials(request) {
		const credentials = auth(request);
		const grantType = request.body.grant_type;

		if (credentials) {
			return {
				clientId: credentials.name,
				clientSecret: credentials.pass
			};
		}

		if (request.body.client_id && request.body.client_secret) {
			return {
				clientId: request.body.client_id,
				clientSecret: request.body.client_secret
			};
		}

		if (isClientAuthenticationRequired(grantType)) {
			if (request.body.client_id) {
				return {
					clientId: request.body.client_id
				};
			}
		}

		throw new Error('Invalid client: cannot retrieve client credentials');
	}

	function isClientAuthenticationRequired(grantType) {
		if (Object.keys(requireClientAuthentication).length > 0) {
			return (typeof requireClientAuthentication[grantType] !== 'undefined') ? requireClientAuthentication[grantType] : true;
		} else {
			return true;
		}
	}

	function handleGrantType(request, client) {
		const grantType = request.body.grant_type;

		if (!grantType) {
			throw new Error('Missing parameter: `grant_type`');
		}

		if (!grantTypes[grantType]) {
			throw new Error('Unsupported grant type: `grant_type` is invalid');
		}

		if (client.grants.indexOf(grantType) < 0) {
			throw new Error('Unauthorized client: `grant_type` is invalid');
		}

		const lifeTime = {
			access: client.accessTokenLifeTime || accessTokenLifeTime,
			refresh: client.refreshTokenLifeTime || refreshTokenLifeTime
		};

		const options = {
			model,
			accessTokenLifeTime: lifeTime.access,
			refreshTokenLifeTime: lifeTime.refresh,
			alwaysIssueNewRefreshToken
		};

		return grantTypes[grantType](options).handle(request, client);
	}

	function getTokenType(model) {
		return BearerToken(model.accessToken, model.accessTokenLifeTime, model.refreshToken, model.scope, model.customAttributes);
	}

	return {
		handle(request, response) {
			if (request.method !== 'POST') {
				throw new Error('Invalid request: method must be POST');
			}

			if (request.headers['content-type'] !== 'application/x-www-form-urlencoded') {
				throw new Error('Invalid request: content must be application/x-www-form-urlencoded');
			}

			const client = getClient(request);
			const data = handleGrantType(request, client);
			const token = getTokenType(TokenModel(data, { allowExtendedTokenAttributes }));

			response.body = token.valueOf();
			response.set('Cache-Control', 'no-store');
			response.set('Pragma', 'no-cache');

			return token;
		}
	};
};