const TYPE = 'refresh_token';
const normalize = require('./normalize');

module.exports = function RefreshToken(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async createToken(res, { body, data, parsedClient , getClient, extensible, tokenRefreshed }) {
			const client = getClient(parsedClient.clientId, parsedClient.clientSecret);
			const refreshTokenId = body.refresh_token;
			
			if (!client) {
				res.statusCode = 400;
				res.end('Invalid client: client does not matched');
			}
			
			if (!refreshTokenId) {
				res.statusCode = 400;
				res.end('Invalid request: missing parameter `refresh_token`');
			}

			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}

			if (extensible) {
				const customAttributes = await finalOptions.token.extend(body);
				data.customAttributes = customAttributes;
			}

			const token = tokenRefreshed(refreshTokenId, data);

			if (!token) {
				res.statusCode = 400;
				res.end('Invalid grant: invalid refresh token');
			}

			await finalOptions.token.store.save(data, client);

			return token;
		}
	};
};