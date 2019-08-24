const modelAttributes = ['accessToken','refreshToken','scope', 'client', 'user'];

module.exports = function (data, options) {
	const {
		accessToken,
		refreshToken,
		scope,
		user,
		client
	} = data;

	if (!accessToken) {
		throw new Error('Missing parameter: `accessToken`');
	}

	if (!client) {
		throw new Error('Missing parameter: `client`');
	}

	if (!user) {
		throw new Error('Missing parameter: `user`');
	}

	return {
		accessToken,
		refreshToken,
		user,
		client,
		scope,
		customAttributes: () => {
			if (options && options.extensible) {
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