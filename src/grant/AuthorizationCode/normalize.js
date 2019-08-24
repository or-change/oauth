const validator = require('../../validateor');
const schema = require('./schema.json');

module.exports = function AuthorizationCodeNormalize(options = {}) {
	validator(schema, options);

	const finalOptions = defaultAuthorizationCodeFactory();

	if (options) {
		const {
			path: _path = finalOptions.path,
			code: _code = finalOptions.code,
			getAuthenticatedUser: _getAuthenticatedUser = finalOptions.getAuthenticatedUser,
			getUserByCredentials: _getUserByCredentials = finalOptions.getUserByCredentials
		} = options;

		finalOptions.getAuthenticatedUser = _getAuthenticatedUser;
		finalOptions.getUserByCredentials = _getUserByCredentials;

		if (typeof _path === 'object') {
			const {
				authorize: _authorize = finalOptions.path.authorize,
				approve: _approve = finalOptions.path.approve,
			} = _path;

			finalOptions.path.approve = _approve;
			finalOptions.path.authorize = _authorize;
		}

		if (typeof _code === 'object') {
			const {
				lifetime: _lifetime = finalOptions.code.lifetime,
				allowEmptyState: _allowEmptyState = finalOptions.code.allowEmptyState,
				Id: _Id = finalOptions.code.Id,
				store: _store = finalOptions.code.store
			} = _code;

			finalOptions.code.lifetime = _lifetime;
			finalOptions.code.allowEmptyState = _allowEmptyState;
			finalOptions.code.Id = _Id;

			if (typeof _store === 'object') {
				const {
					save: _save = finalOptions.code.save,
					get: _get = finalOptions.code.get,
					revoke: _revoke = finalOptions.code.revoke
				} = _store;

				finalOptions.code.store.save = _save;
				finalOptions.code.store.get = _get;
				finalOptions.code.store.revoeke = _revoke;
			}
		}
	}

	return finalOptions;
};

function defaultAuthorizationCodeFactory() {
	const store = {};

	return {
		path: {
			authorize: '/authorize',
			approve: '/approve'
		},
		code: {
			lifetime: 10 * 60 * 10000,
			allowEmptyState: false,
			Id(user, client, scope) {
				return Math.random().toString(16).substr(2, 10);
			},
			store: {
				save(code, user, client) {
					return store[code.id] = Object.assign(code, {user, client});
				},
				get(codeId) {
					return store[codeId];
				},
				revoke(codeId) {
					const match = store[codeId];

					if (match) {
						return delete store[codeId];
					}

					return false;
				}
			},
		},
		getAuthenticatedUser(req) {
			return null;
		},
		getUserByCredentials(username, password) {
			if (username === 'test' && password === 'pass') {
				return 123;
			}

			return null;
		}
	};
}