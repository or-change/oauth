const TYPE = 'password';
const normalize = require('./normalize');

module.exports = function PasswordCredentials(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async createToken(res, { body, data, parsedClient , getClient, extensible, tokenCreated }) {
			const client = getClient(parsedClient.clientId, parsedClient.clientSecret);

			if (!client) {
				res.statusCode = 400;
				res.end('Invalid client: client does not matched');
			}

			if (!body.username || !body.password) {
				res.statusCode = 400;
				res.end('Invalid request, missing parameter `username` or `password`');
			}

			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				res.statusCode = 400;
				res.end('Invalid grant: inavlid scope');
			}

			if (extensible) {
				const customAttributes = await finalOptions.token.extend(body);
				data.customAttributes = customAttributes;
			}

			const user = finalOptions.getUser(body.username, body.password);

			if (!user) {
				res.statusCode = 400;
				res.end('Invalid grant: user does not matched');
			}
			
			const token = tokenCreated(data);

			await finalOptions.token.store.save(data, user, client);

			return token; 
		}
	};
};