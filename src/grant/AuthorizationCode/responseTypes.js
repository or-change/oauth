exports.Code = function codeResponseType({codeId, state = null}) {
	if (!codeId) {
		throw new Error('Missing parameter: `code`');
	}

	return {
		buildRedirectUri(redirectUri) {
			if(!redirectUri) {
				return new Error('Missing parameter: `redirectUri`');
			}

			const uri = new URL(redirectUri);
			uri.search = new URLSearchParams({
				code: codeId,
				state
			});

			return uri;
		} 
	};
};

exports.Token = function tokenResponseType() {
	throw new Error('Not implemented');
};