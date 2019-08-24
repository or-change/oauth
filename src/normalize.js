const AuthorizationCode = require('./grant/AuthorizationCode');
const validator = require('./validateor');
const schema = require('./schema.json');

module.exports = function OAuthOptionsNormalize(options = {}) {
	validator(schema, options);

	const finalOptions = defaultOAuthOptionsFactory();

	if (options) {
		const {
			grantTypes: _grantTypes = finalOptions.grantTypes,
			token: _token = finalOptions.token,
			scope: _scope = finalOptions.scope,
			client: _client = finalOptions.client
		} = options;

		finalOptions.grantTypes = _grantTypes;

		if (typeof _token === 'object') {
			const {
				path: _path = finalOptions.token.path,
				lifetime: _lifetime = finalOptions.token.lifetime,
				extensible: _extensible = finalOptions.token.extensible,
				refreshable: _refreshable = finalOptions.token.refreshable,
				save: _save = finalOptions.token.save,
				Id: _Id = finalOptions.token.Id,
			} = _token;

			if (typeof _Id === 'object') {
				const {
					Access: _Access = finalOptions.token.Id.Access,
					Refresh: _Refresh = finalOptions.token.Id.Refresh
				} = _Id;

				finalOptions.token.Id.Access = _Access;
				finalOptions.token.Id.Refresh = _Refresh;
			}

			if (typeof _lifetime === 'object') {
				const {
					access: _access = finalOptions.token.lifetime.access,
					refresh: _refresh = finalOptions.token.lifetime.refresh
				} = _lifetime;

				finalOptions.token.lifetime.access = _access;
				finalOptions.token.lifetime.refresh = _refresh;
			}

			finalOptions.token.path = _path;
			finalOptions.token.extensible = _extensible;
			finalOptions.token.refreshable = _refreshable;
			finalOptions.token.save = _save;
		}

		if (typeof _scope === 'object') {
			const {
				validate: _validate = finalOptions.scope.validate,
			} = _scope;

			finalOptions.scope.validate = _validate;
		}

		if (typeof _client === 'object') {
			const {
				get: _get = finalOptions.client.get
			} = _client;

			finalOptions.client.get = _get;
		}
	}

	return finalOptions;
};


function defaultOAuthOptionsFactory() {
	const store = {
		token: {
			access: {},
			refresh: {}
		},
		client: {
			'client1': {
				id: 'client1',
				secret: 'pass',
				grants: ['authorization_code'],
				redirectUris: ['http://localhost:2001/oauth/callback']
			},
			'client2': {
				id: 'client2',
				secret: 'pass',
				grants: ['client_credentials', 'password'],
				redirectUris: ['http://localhost:2001/oauth/callback']
			}
		},
	};

	function randomId() {
		return Math.random().toString(16).substr(2, 10);
	}

	return {
		grantTypes: [
			AuthorizationCode()
		],
		token: {
			path: '/token',
			lifetime: {
				access: 60 * 60 * 1000,
				refresh: 14 * 24 * 60 * 60 * 1000,
			},
			extensible: false,
			refreshable: false,
			save(token, user, client) {
				const accessToken = Object.assign(token.accessToken, {
					user,
					client,
					scope: token.scope
				});
				const refreshToken = token.refreshToken ? Object.assign(token.refreshToken, {
					user,
					client,
					scope: token.scope
				}) : null;

				store.token.access[accessToken.id] = accessToken;

				if (refreshToken) {
					store.token.refresh[refreshToken.id] = refreshToken;
				}

				return { user, client, token };
			},
			Id: {
				Access(user, client, scope) {
					return randomId();
				},
				Refresh(user, client, scope) {
					return randomId();
				}
			}
		},
		scope: {
			validate(user, client, scope) {
				return scope || '*';
			}
		},
		client: {
			get(id, secret) {
				const client = store.client[id];

				if (client.secret === secret) {
					return client;
				}

				return null;
			}
		}
	};
}