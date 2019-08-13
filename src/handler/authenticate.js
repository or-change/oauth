module.exports = function AuthenticateHandler(options) {
	const {
		addAcceptedScopesHeader, addAuthorizedScopesHeader,
		allowBearerTokenInQueryString, model, scope
	} = options;

	if (!model) {
		throw new Error('Missing parameter: `model`');
	}

	if (!model.getAccessToken) {
		throw new Error('Invalid argument: model does not implement `getAccessToken()`');
	}

	if (scope && undefined === addAcceptedScopesHeader) {
		throw new Error('Missing parameter: `addAcceptedScopesHeader`');
	}

	if (scope && undefined === addAuthorizedScopesHeader) {
		throw new Error('Missing parameter: `addAuthorizedScopesHeader`');
	}

	if (scope && !model.verifyScope) {
		throw new Error('Invalid argument: model does not implement `verifyScope()`');
	}

	const tokenSource = {
		requestHeader(request) {
			const token = request.headers['Authorization'];
			const matches = token.match(/Bearer\s(\S+)/);

			if (!matches) {
				throw new Error('Invalid request: malformed authorization header');
			}

			return matches[1];
		},
		requestQuery(request) {
			if (!allowBearerTokenInQueryString) {
				throw new Error('Invalid request: do not send bearer tokens in query URLs');
			}

			return request.query.access_token;
		},
		requestBody(request) {
			if (request.method === 'GET') {
				throw new Error('Invalid request: token may not be passed in the body when using the GET verb');
			}

			if (request.headers['content-type'] !== 'application/x-www-form-urlencoded') {
				throw new Error('Invalid request: content must be application/x-www-form-urlencoded');
			}

			return request.body.access_token;
		}
	};

	function getTokenFromRequest(request) {
		const headerToken = request.headers['Authorization'];
		const queryToken = request.query.access_token;
		const bodyToken = request.body.access_token;

		if (!!headerToken + !!queryToken + !!bodyToken > 1) {
			throw new Error('Invalid request: only one authentication method is allowed');
		}

		if (headerToken) {
			return tokenSource.requestHeader(request);
		}

		if (queryToken) {
			return tokenSource.requestQuery(request);
		}

		if (bodyToken) {
			return tokenSource.requestBody(request);
		}

		throw new Error('Unauthorized request: no authentication given');
	}

	function getAccessToken(token) {
		const accessToken = model.getAccessToken(token);
		if (!accessToken) {
			throw new Error('Invalid token: access token is invalid');
		}

		if (!accessToken.user) {
			throw new Error('Server error: `getAccessToken()` did not return a `user` object');
		}

		if (!(accessToken.accessTokenExpiredAt instanceof Date)) {
			throw new Error('Server error: `accessTokenExpiredAt` must be a Date instance');
		}

		if (accessToken.accessTokenExpiredAt < new Date()) {
			throw new Error('Invalid token: access token has expired');
		}

		return accessToken;
	}


	function verifyScope(accessToken) {
		if (!model.verifyScope(accessToken, scope)) {
			throw new Error('Insufficient scope: authorized scope is insufficient');
		}

		return true;
	}

	function updateResponse(response, accessToken) {
		if (scope && addAcceptedScopesHeader) {
			response.set('X-Accepted-OAuth-Scopes', this.scope);
		}

		if (scope && addAuthorizedScopesHeader) {
			response.set('X-OAuth-Scopes', accessToken.scope);
		}
	}

	return {
		handle(request, response) {
			const token = getTokenFromRequest(request);
			const accessToken = getAccessToken(token);

			if (!scope || verifyScope(scope)) {
				return updateResponse(response, accessToken);
			}
			
			throw new Error('Server Error: authenticate failure');
		}
	};
};