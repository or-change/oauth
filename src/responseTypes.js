const url = require('url');

exports.Code = function codeResponseType(code) {
	if (!code) {
		throw new Error('Missing parameter: `code`');
	}

	return {
		code,
		buildRedirectUri(redirectUri) {
			if(!redirectUri) {
				return new Error('Missing parameter: `redirectUri`');
			}

			const uri = url.parse(redirectUri, true);

			uri.query.code = this.code;
			uri.search = null;

			return uri;
		} 
	};
};

exports.Token = function tokenResponseType() {
	throw new Error('Not implemented');
};