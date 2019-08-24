const validator = require('../../validateor');
const schema = require('./schema.json');

module.exports = function ClientCredentialsNormalize(options = {}) {
	validator(schema, options);
	
	const finalOptions = defaultClientCredentialsFactory();

	if (options) {
		const {
			getUserFromClient: _getUserFromClient = finalOptions.getUserFromClient
		} = options;

		finalOptions.getUserFromClient = _getUserFromClient;
	}

	return finalOptions;
};

function defaultClientCredentialsFactory() {
	return {
		getUserFromClient(client) {
			return client.id === 'client' ? {user: 123 } : null;
		}
	};
}