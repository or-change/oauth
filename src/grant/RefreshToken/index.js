const TYPE = 'refresh_token';
const normalize = require('./normalize');

module.exports = function RefreshToken(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async createToken({ res, body, clientQuery, token }) {
			const client = await token.queryClient(clientQuery.id, clientQuery.secret);
			const refreshToken = body.refresh_token;
			
			if (!client) {
				res.statusCode = 400;
				res.end('Invalid client: client does not matched');
			}
			
			if (!refreshToken) {
				res.statusCode = 400;
				res.end('Invalid request: missing parameter `refresh_token`');
			}

			if (!finalOptions.scope.validate(finalOptions.scope.accept, token.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}

			const extension = finalOptions.token.set(finalOptions.token.extensibleAttributes, body);

			if (extension) {
				token.extends(extension);
			}

			const isRefreshed = await token.refreshed(refreshToken);

			if (!isRefreshed) {
				res.statusCode = 400;
				res.end('Invalid grant: refresh token validate failed.');
			} 
			
			await finalOptions.token.store.save({
				accessToken: token.accessToken,
				refreshToken: token.refreshToken,
				scope: token.scope,
				extension
			}, client);

		}
	};
};