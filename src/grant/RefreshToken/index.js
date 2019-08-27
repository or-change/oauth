const TYPE = 'refresh_token';
const normalize = require('./normalize');

module.exports = function RefreshToken(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async tokenHandler({ body, data, client, tokenRefreshed }) {
			const refreshTokenId = body.refresh_token;
			
			if (!refreshTokenId) {
				throw new Error('Invalid request: missing parameter `refresh_token`');
			}

			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				throw new Error('Invalid grant: inavlid scope');
			}

			const token = tokenRefreshed(refreshTokenId, data);

			if (!token) {
				throw new Error('Invalid grant: invalid refresh token');
			}

			await finalOptions.saveToken(data, client);

			return token;
		}
	};
};