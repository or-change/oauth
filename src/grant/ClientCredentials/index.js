const TYPE = 'client_credentials';
const normalize = require('./normalize');

module.exports = function ClientCredentials(options = {}) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: false,
		async createToken(res, { body, data, parsedClient, getClient, extensible, tokenCreated }) {
			const client = getClient(parsedClient.clientId, parsedClient.clientSecret);

			if (!client) {
				res.statusCode = 400;
				res.end('Invalid client: client does not matched');
			}
			
			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}

			if (extensible) {
				const customAttributes = await finalOptions.token.extend(body);
				data.customAttributes = customAttributes;
			}

			const token = tokenCreated(data);

			await finalOptions.token.store.save(data, client);

			return token;
		}
	};
};