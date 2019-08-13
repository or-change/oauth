module.exports = function (options) {
	const { accessTokenLifeTime, model, refreshTokenLifeTime, alwaysIssueNewRefreshToken } = options;

	if (!options.model) {
		throw new Error('Missing parameter: `model`');
	}

	if (!options.model.getAuthorizationCode) {
		throw new Error('Invalid argument: model does not implement `getAuthorizationCode()`');
	}

	if (!options.model.revokeAuthorizationCode) {
		throw new Error('Invalid argument: model does not implement `revokeAuthorizationCode()`');
	}

	if (!options.model.saveToken) {
		throw new Error('Invalid argument: model does not implement `saveToken()`');
	}

	function getAuthorizationCode(request, client) {
		const code = model.getAuthorizationCode(request.body.code);

		if (!code) {
			throw new Error('Invalid grant: authorization code is invalid');
		}

		if (!code.client) {
			throw new Error('Server error: `getAuthorizationCode()` did not return a `client` object');
		}

		if (!code.user) {
			throw new Error('Server error: `getAuthorizationCode()` did not return a `user` object');
		}

		if (code.client.id !== client.id) {
			throw new Error('Invalid grant: authorization code is invalid');
		}

		if (!(code.expiresAt instanceof Date)) {
			throw new Error('Server error: `expiresAt` must be a Date instance');
		}

		if (code.expiresAt < new Date()) {
			throw new Error('Invalid grant: authorization code has expired');
		}

		return code;
	}

	function revokeAuthorizationCode(code) {
		const status = model.revokeAuthorizationCode(code);

		if (!status) {
			throw new Error('Invalid grant');
		}

		return code;
	}

	function saveToken(user, client, authorizationCode, scope) {
		const token = {
			scope: validateScope(user, client, scope),
			accessToken: genAccessToken(user, client, scope),
			accessTokenExpiredAt: getExpiredAt(accessTokenLifeTime),
			refreshToken: genRefreshToken(user, client, scope),
			refreshTokenExpiredAt: getExpiredAt(refreshTokenLifeTime)
		};

		model.saveToken(token, user, client);
		
		return Object.assign(token, {user, client }); 
	}

	function validateRedirectUri(request, code) {
		if (!code.redirectUri) {
			return null;
		}

		const redirectUri = request.body.redirect_uri || request.query.redirect_uri;
		const urlReg = /^[a-zA-Z][a-zA-Z0-9+.-]+:/;

		if (!urlReg.test(redirectUri) || redirectUri !== code.redirectUri) {
			throw new Error('Invalid request: `redirect_uri` is invalid');
		}

		return true;
	}

	function validateScope(user, client, scope) {
		if (model.validateScope) {
			const validatedScope = model.validateScope(user, client, scope);

			if (!validatedScope) {
				throw new Error('Invalid scope: Requested scope is invalid');
			}

			return validatedScope;
		} else {
			return scope;
		}
	}

	function genAccessToken(user, client, scope) {
		if (model.genAccessToken) {
			const accessToken = model.genAccessToken(user, client, scope);

			return accessToken || null;
		}
	}

	function genRefreshToken(user, client, scope) {
		if (model.genAccessToken) {
			const refreshToken = model.genRefreshToken(user, client, scope);

			return refreshToken || null;
		}
	}

	function getExpiredAt(lifeTime) {
		const expired = new Date();

		expired.setSeconds(expired.getSeconds() + lifeTime);

		return expired;
	}

	return {
		accessTokenLifeTime, refreshTokenLifeTime,
		alwaysIssueNewRefreshToken, model,
		handle(request, client) {
			const code = getAuthorizationCode(request, client);

			if (validateRedirectUri(request, code) && revokeAuthorizationCode(code)) {
				const token = saveToken(code.user, client, code.code, code.scope);
				
				return token;
			} else {
				throw new Error('authorization failure');
			}
		}
	};
};