const TYPE = 'client_credentials';
const normalize = require('./normalize');

module.exports = function ClientCredentials(options = {}) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: false,
		async tokenHandler({ data, client, tokenCreated }) {
			if (!finalOptions.scope.validate(finalOptions.scope.accept, data.scope, finalOptions.scope.valueValidate)) {
				throw new Error('Invalid grant: inavlid scope');
			}

			const token = tokenCreated(data);

			await finalOptions.saveToken(data, client);

			return token;
		}
	};
};