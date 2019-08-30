const crypto = require('crypto');
const AuthorizationCode = require('./grant/AuthorizationCode');
const Ajv = require('ajv');
const ajv = new Ajv;
require('ajv-keywords')(ajv, ['instanceof']);
const schema = require('./schema.json');

module.exports = function OAuthOptionsNormalize(options = {}) {
	const validate = ajv.compile(schema);
	const valid = validate(options);

	if (!valid) {
		validate.errors.forEach(error => {
			console.log(error);
		});

		throw new Error(JSON.stringify(validate.errors));
	}

	const finalOptions = defaultOAuthOptionsFactory();

	if (options) {
		const {
			grantTypes: _grantTypes = finalOptions.grantTypes,
			prefix: _prefix = finalOptions.prefix,
			token: _token = finalOptions.token,
			scope: _scope = finalOptions.scope,
			client: _client = finalOptions.client
		} = options;

		finalOptions.grantTypes = _grantTypes;
		finalOptions.prefix = _prefix;

		if (typeof _token === 'object') {
			const {
				path: _path = finalOptions.token.path,
				lifetime: _lifetime = finalOptions.token.lifetime,
				extensible: _extensible = finalOptions.token.extensible,
				refreshable: _refreshable = finalOptions.token.refreshable,
				save: _save = finalOptions.token.save,
				Id: _Id = finalOptions.token.Id,
				refreshed: _refreshed = finalOptions.token.refreshed
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
			finalOptions.token.refreshed = _refreshed;
		}

		if (typeof _scope === 'object') {
			const {
				default: _default = finalOptions.scope.default,
				accept: _accpet = finalOptions.scope.accept,
				set: _set = finalOptions.scope.set,
				valueset: _valueValidate = finalOptions.scope.valueValidate
			} = _scope;

			finalOptions.scope.scope = _default;
			finalOptions.scope.accept = _accpet;
			finalOptions.scope.validate = _set;
			finalOptions.scope.valueValidate = _valueValidate;
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
				grants: ['client_credentials', 'password', 'refresh_token'],
				redirectUris: ['http://localhost:2001/oauth/callback']
			}
		},
	};
	const counter = {
		num: 1
	};

	function randomId() {
		const data = `${counter.num++}-${Date.now()}-${Math.random().toString(16).substr(2, 8)}`;

		return crypto.createHash('sha256').update(data).digest('base64');
	}

	return {
		grantTypes: [AuthorizationCode()],
		prefix: '/oauth',
		token: {
			path: '/token',
			lifetime: {
				access: 60 * 60 * 1000,
				refresh: 14 * 24 * 60 * 60 * 1000,
			},
			extensible: false,
			refreshable: true,
			save(token, grant) {
				const accessToken = Object.assign({}, token.accessToken, {
					grant,
					scope: token.scope
				});
				const refreshToken = token.refreshToken ? Object.assign({}, token.refreshToken, {
					scope: token.scope
				}) : null;

				store.token.access[token.accessToken.id] = accessToken;

				if (refreshToken) {
					store.token.refresh[token.refreshToken.id] = refreshToken;
				}

				return true;
			},
			Id: {
				Access() {
					return randomId();
				},
				Refresh() {
					return randomId();
				}
			},
			refreshed(id) {
				const originalRefreshToken = store.token.refresh[id];

				if (originalRefreshToken && originalRefreshToken.expiredAt > Date.now()) {
					return delete store.token.refresh[id];
				}

				return false;
			}
		},
		client: {
			get(id, secret, isAuthorize = false) {
				const client = store.client[id];

				if (isAuthorize || client.secret === secret) {
					return client;
				}

				return null;
			}
		},
		scope: {
			default: '*',
			accept: ['*'],
			set(accept, scope, valueValidate) {
				if (!scope) {
					return '*';
				}
				
				const scopes = scope.split(/\s+/);

				if (accept.length < scopes.length) {
					return false;
				}

				for (const value of scopes.values()) {
					if (accept.indexOf(value) < 0) {
						return false;
					}
				}

				if(valueValidate(scopes)) {
					return scope;
				}

				return null;
			},
			valueValidate(scopes) {
				return true;
			}
		}
	};
}