module.exports = function clientCredentialsFactory(options) {
	const {
		accessTokenLifeTime,
		refreshTokenLifeTime,
		alwaysIssueNewRefreshToken,
		model
	} = options;

	if (!model) {
		throw new Error('Missing parameter: `model`');
	}

	if (!model.getUserFromClient) {
		throw new Error('Invalid argument: model does not implement `getUserFromClient()`');
	}

	if (!model.saveToken) {
		throw new Error('Invalid argument: model does not implement `saveToken()`');
	}

	function getUserFromClient(client) {
		const user = model.getUserFromClient(client);

		if (!user) {
			throw new Error('Invalid grant: user credentials are invalid');
		}

		return user;
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

	function getExpiredAt() {
		const expired = new Date();

		expired.setSeconds(expired.getSeconds() + accessTokenLifeTime);

		return expired;
	}
	function saveToken(user, client, scope) {
		const token = {
			accessToken: genAccessToken(user, client, scope),
			accessTokenExpiredAt: getExpiredAt(),
			scope: validateScope(user, client, scope)
		};

		model.saveToken(token, user, client);

		return Object.assign(token, { user, client});
	}

	return {
		accessTokenLifeTime, refreshTokenLifeTime,
		alwaysIssueNewRefreshToken, model,
		handle(request, client) {
			const user = getUserFromClient(client);

			return saveToken(user, client, this.scope);
		}
	};
};