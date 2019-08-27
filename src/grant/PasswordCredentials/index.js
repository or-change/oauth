const TYPE = 'password';
const normalize = require('./normalize');

module.exports = function PasswordCredentials(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async tokenHandler({ body, data, client, tokenCreated }) {
			if (!body.username || !body.password) {
				throw new Error('Invalid request, missing parameter `username` or `password`');
			}

			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				throw new Error('Invalid grant: inavlid scope');
			}

			const user = finalOptions.getUser(body.username, body.password);
			const token = tokenCreated(data);

			await finalOptions.saveToken(data, user, client);

			return token; 
		}
	};
};