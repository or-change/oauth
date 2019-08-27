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
				extend: _extend = finalOptions.token.extend,
				created: _created = finalOptions.token.created,
				refreshed: _refreshed = finalOptions.token.refershed
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
			finalOptions.token.extend = _extend;
			finalOptions.token.created = _created;
			finalOptions.token.refershed = _refreshed;
		}

		if (typeof _scope === 'object') {
			const {
				default: _default = finalOptions.scope.default,
				accept: _accpet = finalOptions.scope.accept,
				validate: _validate = finalOptions.scope.validate,
				valueValidate: _valueValidate = finalOptions.scope.valueValidate
			} = _scope;

			finalOptions.scope.scope = _default;
			finalOptions.scope.accept = _accpet;
			finalOptions.scope.validate = _validate;
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
		grantTypes: [
			AuthorizationCode()
		],
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
				const accessToken = Object.assign(token.accessToken, {
					grant,
					scope: token.scope
				});
				const refreshToken = token.refreshToken ? Object.assign(token.refreshToken, {
					grant,
					scope: token.scope
				}) : null;

				store.token.access[accessToken.id] = accessToken;

				if (refreshToken) {
					store.token.refresh[refreshToken.id] = refreshToken;
				}

				return true;
			},
			extend(data) {
				const customAttributes = {};
				const modelAttributes = ['accessToken', 'refreshToken', 'scope', 'client', 'user'];

				for (var key in data) {
					if (data.hasOwnProperty(key) && (modelAttributes.indexOf(key) < 0)) {
						customAttributes[key] = data[key];
					}
				}

				return customAttributes;
			},
			Id: {
				Access() {
					return randomId();
				},
				Refresh() {
					return randomId();
				}
			},
			created(data) {
				const token = {
					access_token: data.accessToken.id,
					token_type: 'Bearer',
					expires_in: data.accessToken.expiredAt
				};

				if (data.refreshToken) {
					token.refresh_token = data.refreshToken.id;
				}

				if (data.scope) {
					token.scope = data.scope;
				}

				for (var key in data.customAttributes) {
					if (data.customAttributes.hasOwnProperty(key)) {
						token[key] = data.customAttributes[key];
					}
				}

				return token;
			},
			refershed(id, data) {
				const originalRefreshToken = store.token.refresh[id];

				if (originalRefreshToken && originalRefreshToken.expiredAt > Date.now()) {
					delete store.token.refresh[id];
					const token = {
						access_token: data.accessToken.id,
						token_type: 'Bearer',
						expires_in: data.accessToken.expiredAt
					};

					if (data.refreshToken) {
						token.refresh_token = data.refreshToken.id;
					}

					if (data.scope) {
						token.scope = data.scope;
					}

					for (var key in data.customAttributes) {
						if (data.customAttributes.hasOwnProperty(key)) {
							token[key] = data.customAttributes[key];
						}
					}

					return token;
				}

				return null;
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
		},
		scope: {
			default: '*',
			accept: ['*'],
			validate(accept, scope, valueValidate) {
				const scopes = scope.split(/\s+/);

				if (accept.length < scopes.length) {
					return false;
				}

				for (const value of scopes.values()) {
					if (accept.indexOf(value) < 0) {
						return false;
					}
				}

				return valueValidate(scopes);
			},
			valueValidate(scopes) {
				return true;
			}
		}
	};
}