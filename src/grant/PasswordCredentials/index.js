const TYPE = 'password';
const normalize = require('./normalize');

module.exports = function PasswordCredentials(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async createToken({ res, body, clientQuery, token }) {
			const client = await token.queryClient(clientQuery.id, clientQuery.secret);

			if (!client) {
				res.statusCode = 400;
				res.end('Invalid client: client does not matched');
			}

			if (!body.username || !body.password) {
				res.statusCode = 400;
				res.end('Invalid request, missing parameter `username` or `password`');
			}

			if (!finalOptions.scope.validate(finalOptions.scope.accept, token.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}

			const user = finalOptions.getUser(body.username, body.password);

			if (!user) {
				res.statusCode = 400;
				res.end('Invalid grant: user does not matched');
			}
			
			const extension = finalOptions.token.set(finalOptions.token.extensibleAttributes, body);

			if (extension) {
				token.extends(extension);
			}

			await finalOptions.token.store.save({
				accessToken: token.accessToken,
				refreshToken: token.refreshToken,
				scope: token.scope,
				extension
			}, user, client);
		}
	};
};