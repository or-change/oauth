const modelAttributes = [
	'accessToken', 'accessTokenExpiredAt',
	'refreshToken', 'refreshTokenExpiredAt',
	'scope', 'client', 'user'
];


module.exports = function (data, options) {
	const {
		accessToken, accessTokenExpiredAt,
		refreshToken, refreshTokenExpiredAt,
		scope, user, client
	} = data;
	const accessTokenLifeTime = Math.floor(accessTokenExpiredAt - new Date());

	if (!accessToken) {
		throw new Error('Missing parameter: `accessToken`');
	}

	if (!client) {
		throw new Error('Missing parameter: `client`');
	}

	if (!user) {
		throw new Error('Missing parameter: `user`');
	}

	if (accessTokenExpiredAt && !(accessTokenExpiredAt instanceof Date)) {
		throw new Error('Invalid parameter: `accessTokenExpiredAt`');
	}

	if (refreshTokenExpiredAt && !(refreshTokenExpiredAt instanceof Date)) {
		throw new Error('Invalid parameter: `refreshTokenExpiredAt`');
	}


	return {
		accessToken, accessTokenExpiredAt,
		refreshToken, refreshTokenExpiredAt,
		user, client, scope,
		accessTokenLifeTime,
		customAttributes: () => {
			if (options && options.allowExtendedTokenAttributes) {
				const customAttributes = {};

				for (var key in data) {
					if (data.hasOwnProperty(key) && (modelAttributes.indexOf(key) < 0)) {
						customAttributes[key] = data[key];
					}
				}

				return customAttributes;
			}

			return null;
		}
	};
};