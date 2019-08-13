const AuthenticateHandler = require('./handler/authenticate');
const AuthorizeHandler = require('./handler/authorize');
const TokenHandler = require('./handler/token');

module.exports = function OAuthServer(options) {
	if (!options.model) {
		throw new Error('Missing parameter: `model`');
	}

	return {
		options,
		authenticate(request, response, options) {
			if (typeof options === 'string') {
				options = { scope: options };
			}

			const authenticateOptions = Object.assign({
				addAcceptedScopesHeader: true,
				addAuthorizedScopesHeader: true,
				allowBearerTokensInQueryString: false
			}, this.options, options);

			return AuthenticateHandler(authenticateOptions).handle(request, response);
		},
		authorize(request, response, options) {
			const authorizeOptions = Object.assign({
				allowEmptyState: false,
				authorizationCodeLifeTime: 5 * 60 * 1000  // 5 min.
			}, this.options, options);

			return AuthorizeHandler(authorizeOptions).handle(request, response);
		},
		token(request, response, options) {
			const tokenOptions = Object.assign({
				accessTokenLifeTime: 60 * 60 * 1000,            // 1 hour.
				refreshTokenLifeTime: 60 * 60 * 24 * 14 * 1000,  // 2 weeks.
				allowExtendedTokenAttributes: false,
				requireClientAuthentication: {}
			}, this.options, options);

			return TokenHandler(tokenOptions).handle(request, response);
		}
	};
};