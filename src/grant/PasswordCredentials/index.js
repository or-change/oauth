const TYPE = 'password';
const normalize = require('./normalize');

module.exports = function PasswordCredentials(options) {
	const finalOptions = normalize(options);

	return {
		type: TYPE,
		refreshable: true,
		async queryUser({ getCredentials }) {
			const credentials = getCredentials();

			return finalOptions.getUser(credentials.username, credentials.password);
		}
	};
};