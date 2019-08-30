const BASIC_REG = /^ *(?:[Bb][Aa][Ss][Ii][Cc]) +([A-Za-z0-9._~+/-]+=*) *$/;
const USER_INFO_REG = /^([^:]*):(.*)$/;

exports.ClientQuery = function ({ body, query, headers }) {
	const clientId = body.client_id || query['client_id'];

	if (clientId === 'undefined' && headers.authorization === 'undefined') {
		throw new Error('Invalid request: only one authentication method is allowed');
	}

	if (clientId) {
		return {
			id: clientId,
			secret: body.client_secret || query['client_secret']
		};
	}

	if (headers.authorization) {
		const { authorization } = headers;
		const match = BASIC_REG.exec(authorization);

		if (!match) {
			return null;
		}

		const clientInfo = USER_INFO_REG.exec(Buffer.from(match[1], 'base64').toString());

		if (!clientInfo[2]) {
			return {
				id: clientInfo[1]
			};
		}

		return {
			id: clientInfo[1],
			secret: clientInfo[2]
		};
	}
};