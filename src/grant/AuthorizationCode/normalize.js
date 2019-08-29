const path = require('path');
const Ajv = require('ajv');
const ajv = new Ajv;
require('ajv-keywords')(ajv, ['instanceof']);
const schema = require('./schema.json');

module.exports = function AuthorizationCodeNormalize(options = {}) {
	const validate = ajv.compile(schema);
	const valid = validate(options); 

	if (!valid) {
		validate.errors.forEach(error => {
			console.log(error);
		});

		throw new Error(JSON.stringify(validate.errors));
	}

	const finalOptions = defaultAuthorizationCodeFactory();

	if (options) {
		const {
			path: _path = finalOptions.path,
			code: _code = finalOptions.code,
			userAuthenticate: _userAuthenticate = finalOptions.userAuthenticate,
			scope: _scope = finalOptions.scope,
			token: _token = finalOptions.token
		} = options;

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

		if (typeof _userAuthenticate === 'object') {
			const {
				getAuthenticatedUser: _getAuthenticatedUser = finalOptions.userAuthenticate.getAuthenticatedUser,
				getUserByCredentials: _getUserByCredentials = finalOptions.userAuthenticate.getUserByCredentials
			} = _userAuthenticate;

			finalOptions.userAuthenticate.getAuthenticatedUser = _getAuthenticatedUser;
			finalOptions.userAuthenticate.getUserByCredentials = _getUserByCredentials;
		}

		if (typeof _scope === 'object') {
			const {
				default: _default = finalOptions.saveToken.default,
				accept: _accpet = finalOptions.scope.accept,
				validate: _validate = finalOptions.scope.validate,
				valueValidate: _valueValidate = finalOptions.scope.valueValidate
			} = _scope;

			finalOptions.scope.default = _default;
			finalOptions.scope.accept = _accpet;
			finalOptions.scope.validate = _validate;
			finalOptions.scope.valueValidate = _valueValidate;
		}

		if (typeof _token === 'object') {
			const {
				store: _store = finalOptions.token.store,
				extensibleAttributes: _extensibleAttributes = finalOptions.token.extensibleAttributes,
				extend: _extend = finalOptions.token.extend
			} = _token;

			finalOptions.token.extensibleAttributes = _extensibleAttributes;
			finalOptions.token.extend = _extend;
			
			if (typeof _store === 'object') {
				const {
					save: _save = finalOptions.token.store.save
				} = _store;

				finalOptions.token.store.save = _save;
			}
		}
	}

	return finalOptions;
};

function defaultAuthorizationCodeFactory() {
	const store = {
		token: {
			access: {},
			refresh: {}
		},
		code: {}
	};

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
					return store.code[code.id] = Object.assign(code, {user, client});
				},
				get(codeId) {
					return store.code[codeId];
				},
				revoke(codeId) {
					const match = store.code[codeId];

					if (match) {
						return delete store.code[codeId];
					}

					return false;
				}
			},
		},
		userAuthenticate: {
			approvePagePath: path.join(__dirname, 'approve.ejs'),
			getAuthenticatedUser(req) {
				return null;
			},
			getUserByCredentials(username, password) {
				if (username === 'test' && password === 'pass') {
					return 123;
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
		},
		token: {
			store: {
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
		
					return true;
				},
			},
			extensibleAttributes: [],
			extend(extensibleAttributes, body) {
				const customAttributes = {};
				const RequestParameters = ['grant_type', 'client_id', 'client_secret', 'username', 'password', 'refresh_token', 'redirect_uri', 'code', 'scope'];

				if (extensibleAttributes.length === 0) {
					return null;
				}
				
				for (var key in body) {
					if (body.hasOwnProperty(key) && (RequestParameters.indexOf(key) < 0) && extensibleAttributes.indexOf(key) > 0) {
						customAttributes[key] = body[key];
					}
				}

				return customAttributes;
			}
		}
	};
}