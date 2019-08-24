const TYPE = 'client_credentials';
const normalize = require('./normalize');

module.exports = function ClientCredentials(options = {}) {
	const finalOptions = normalize(options);
	
	return {
		type: TYPE,
		refreshable: false,
		async queryUser({ client }) {
			return finalOptions.getUserFromClient(client);
		},
	};
};