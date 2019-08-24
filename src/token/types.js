exports.BearerToken = function ({ accessToken, refreshToken, scope, customAttributes }) {
	if (!accessToken) {
		throw new Error('Missing parameter: `accessToken`');
	}

	return {
		accessToken,
		refreshToken,scope,
		customAttributes: customAttributes || null,
		valueOf() {
			const obj = {
				access_token: accessToken.id,
				token_type: 'Bearer',
				expires_in: accessToken.expriedAt
			};

			if (refreshToken) {
				obj.refresh_token = refreshToken.id;
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
