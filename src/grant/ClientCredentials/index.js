const TYPE = 'client_credentials';
const normalize = require('./normalize');

module.exports = function ClientCredentials(options = {}) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: false,
		async createToken({ res, body, clientQuery, token }) {
			const client = await token.queryClient(clientQuery.id, clientQuery.secret);

			if (!client) {
				res.statusCode = 400;
				res.end('Invalid client: client does not matched');
			}
			
			if (!finalOptions.scope.validate(finalOptions.scope.accept, token.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}

			const extension = finalOptions.token.set(finalOptions.token.extensibleAttributes, body);

			if (extension) {
				token.extends(extension);
			}

			await finalOptions.token.store.save({
				accessToken: token.accessToken,
				scope: token.scope
			}, client);
		}
	};
};