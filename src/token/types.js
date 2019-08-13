exports.BearerToken = function (accessToken, accessTokenLifeTime, refreshToken, scope, customAttributes) {
	if (!accessToken) {
		throw new Error('Missing parameter: `accessToken`');
	}

	return {
		accessToken, accessTokenLifeTime,
		refreshToken, scope,
		customAttributes: customAttributes || null,
		valueOf() {
			const obj = {
				access_token: accessToken,
				token_type: 'Bearer'
			};

			if (accessTokenLifeTime) {
				obj.expires_in = accessTokenLifeTime;
			}

			if (refreshToken) {
				obj.refresh_token = refreshToken;
			}

			if (scope) {
				obj.scope = scope;
			}

			for (var key in customAttributes) {
				if (customAttributes.hasOwnProperty(key)) {
					obj[key] = customAttributes[key];
				}
			}
			return obj;
		}
	};
};

exports.MacToken = function () {
	throw new Error('Not implemented.');
};
