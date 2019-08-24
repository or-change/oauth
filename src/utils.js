const BASIC_REG = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/;
const USER_INFO_REG = /^([^:]*):(.*)$/;

exports.authorizationParser = function auth({ body, query, headers }) {
	const clientId = body.client_id || query.get('client_id');

	if (!!clientId + !!headers.authorization > 1) {
		throw new Error('Invalid request: only one authentication method is allowed');
	}

	if (clientId) {
		return {
			clientId,
			clientSecret: body.client_secret || query.get('client_secret')
		};
	}

	if (headers.authorization) {
		const { authorization } = headers;
		const match = BASIC_REG.exec(authorization);

		if (!match) {
			return null;
		}

		const userInfo = USER_INFO_REG.exec(Buffer.from(match[1], 'base64').toString());

		if (!userInfo) {
			return null;
		}

		return {
			clientId: userInfo[1],
			clientSecret: userInfo[2]
		};
	}
};