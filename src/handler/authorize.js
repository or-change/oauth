const url = require('url');
const AuthenticateHandler = require('../handler/authenticate');
const responseTypes = {
	code: require('../responseTypes').Code,
	token: require('../responseTypes').Token
};

module.exports = function (options) {
	const {
		model,
		allowEmptyState = false,
		authenticateHandler = AuthenticateHandler(options),
		authorizationCodeLifeTime,
	} = options;

	if (authenticateHandler && !authenticateHandler.handle) {
		throw new Error('Invalid argument: authenticateHandler does not implement `handle()`');
	}

	if (!authorizationCodeLifeTime) {
		throw new Error('Missing parameter: `authorizationCodeLifetime`');
	}

	if (!model) {
		throw new Error('Missing parameter: `model`');
	}

	if (!model.getClient) {
		throw new Error('Invalid argument: model does not implement `getClient()`');
	}

	if (!model.saveAuthorizationCode) {
		throw new Error('Invalid argument: model does not implement `saveAuthorizationCode()`');
	}

	if (!model.genAuthorizationCode) {
		throw new Error('Miss parameter: model does not implement `genAuthorizationCode()`');
	}

	function getAuthorizationCodeLifetime() {
		const expired = new Date();

		expired.setSeconds(expired.getSeconds() + authorizationCodeLifeTime);

		return expired;
	}

	function getClient(request) {
		const clientId = request.body.client_id || request.query.client_id;

		if (!clientId) {
			throw new Error('Missing parameter: `client_id`');
		}

		const redirectUri = request.body.redirect_uri || request.query.redirect_uri;
		const urlReg = /^[a-zA-Z][a-zA-Z0-9+.-]+:/;

		if (redirectUri && !urlReg.test(redirectUri)) {
			throw new Error('Invalid request: `redirect_uri` is not a valid URI');
		}

		const client = model.getClient(clientId, null);

		if (!client) {
			throw new Error('Invalid client: client credentials are invalid');
		}

		if (!client.grants) {
			throw new Error('Invalid client: missing client `grants`');
		}

		if (client.grants.indexOf('authorization_code') < 0) {
			throw new Error('Unauthorized client: `grant_type` is invalid');
		}

		if (!client.redirectUris || 0 === client.redirectUris.length) {
			throw new Error('Invalid client: missing client `redirectUri`');
		}

		if (redirectUri && client.redirectUris.indexOf(redirectUri) < 0) {
			throw new Error('Invalid client: `redirect_uri` does not match client value');
		}

		return client;
	}

	function getScope(request) {
		const scope = request.body.scope || request.query.scope;

		return scope;
	}

	function getUser(request, response) {
		return authenticateHandler.handle(request, response);
	}


	function getState(request) {
		const state = request.body.state || request.query.state;

		if (!allowEmptyState && !state) {
			throw new Error('Missing parameter: `state`');
		}

		return state;
	}

	function getRedirectUri(request, client) {
		return request.body.redirect_uri || request.query.redirect_uri || client.redirectUris[0];
	}

	function getResponseType(request) {
		const responseType = request.body.response_type || request.query.response_type;

		if (!responseType) {
			throw new Error('Missing parameter: `response_type`');
		}

		if (!responseTypes[responseType]) {
			return new Error('Unsupported response type: `response_type` is not supported');
		}

		return responseTypes[responseType];
	}

	function updateResponse(response, redirectUri, state) {
		redirectUri.query = redirectUri.query || {};

		if (state) {
			redirectUri.query.state = state;
		}

		response.redirect(url.format(redirectUri));
	}

	function saveAuthorizationCode(authorizationCode, expiredAt, scope, client, redirectUri, user) {
		const code = { authorizationCode, expiredAt, scope, client, redirectUri, user };

		return model.saveAuthorizationCode(code, user, client);
	}

	function genAuthorizationCode(user, client, scope) {
		return model.genAuthorizationCode(user, client, scope);
	}

	function buildSuccessRedirectUri(redirectUri, responseType) {
		return responseType.buildRedirectUri(redirectUri);
	}

	function buildErrorRedirectUri(redirectUri, error) {
		const uri = url.parse(redirectUri);
		uri.query = { error: error.name };

		if (error.message) {
			uri.query.error_description = error.message;
		}

		return uri;
	}

	return {
		handle(request, response) {
			if ('false' === request.query.allowed) {
				throw new Error('Access denied: user denied access to application');
			}

			const expiredAt = getAuthorizationCodeLifetime();
			const user = getUser(request, response);
			const client = getClient(request);
			const uri = getRedirectUri(request, client);
			const scope = getScope(request);
			const authorizationCode = genAuthorizationCode(user, client, scope);
			const code = saveAuthorizationCode(authorizationCode, expiredAt, scope, client, uri, user);
			const responseType = getResponseType(request)(code.authorizationCode);
			const redirectUri = buildSuccessRedirectUri(uri, responseType);

			updateResponse(response, redirectUri, getState(request));
			
			return code;
		}
	};
};