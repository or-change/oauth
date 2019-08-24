const validator = require('../../validateor');
const schema = require('./schema.json');

module.exports = function PasswordCredentialsNormalize(options = {}) {
	validator(schema, options);

	const finalOptions = defaultClientCredentialsFactory();

	if (options) {
		const {
			getUser: _getUser = finalOptions.getUser
		} = options;

		finalOptions.getUser = _getUser;
	}

	return finalOptions;
};

function defaultClientCredentialsFactory() {
	return {
		getUser(username, password) {

			if (username === 'admin' && password === 'pass') {
				return {
					username: 'admin',
					password: 'pass'
				};
			}

			return null;
		}
	};
}