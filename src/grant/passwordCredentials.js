module.exports = function (options) {
	const {
		accessTokenLifeTime,
		model,
		refreshTokenLifeTime,
		alwaysIssueNewRefreshToken
	} = options;

	if (!model) {
		throw new Error('Missing parameter: `model`');
	}

	if (!model.getUser) {
		throw new Error('Invalid argument: model does not implement `getUser()`');
	}

	if (!model.saveToken) {
		throw new Error('Invalid argument: model does not implement `saveToken()`');
	}

	function getUser(request) {
		if (!request.body.username) {
			throw new Error('Missing parameter: `username`');
		}

		if (!request.body.password) {
			throw new Error('Missing parameter: `password`');
		}

		const user = model.getUser(request.body.username, request.body.password);

		if (!user) {
			throw new Error('Invalid grant: user credentials are invalid');
		}

		return user;
	}

	function saveToken(user, client, scope) {
		const token = {
			scope: validateScope(user, client, scope),
			accessToken: genAccessToken(user, client, scope),
			accessTokenExpiredAt: getExpiredAt(accessTokenLifeTime),
			refreshToken: genRefreshToken(user, client, scope),
			refreshTokenExpiredAt: getExpiredAt(refreshTokenLifeTime)
		};

		model.saveToken(token, user, client);
		
		return Object.assign(token,{ user, client}); 
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
			const user = getUser(request);

			return saveToken(user, client, request.body.scope);
		}
	};
};