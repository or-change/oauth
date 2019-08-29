const Ajv = require('ajv');
const ajv = new Ajv;
require('ajv-keywords')(ajv, ['instanceof']);
const schema = require('./schema.json');

module.exports = function RefreshTokenNormalize(options = {}) {
	const validate = ajv.compile(schema);
	const valid = validate(options);

	if (!valid) {
		validate.errors.forEach(error => {
			console.log(error);
		});

		throw new Error(JSON.stringify(validate.errors));
	}

	const finalOptions = defaultRefreshTokenFactory();

	if (options) {
		const {
			scope: _scope = finalOptions.scope,
			token: _token = finalOptions.token
		} = options;

		if (typeof _scope == 'object') {
			const {
				accept: _accept = finalOptions.scope.accept,
				validate: _validate = finalOptions.scope.validate,
				valueValidate: _valueValidate = finalOptions.scope.valueValidate
			} = _scope;

			finalOptions.scope.accept = _accept;
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

function defaultRefreshTokenFactory() {
	const store = {
		token: {
			access: {},
			refresh: {}
		}
	};
	
	return {
		scope: {
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
				save(token, client) {
					const accessToken = Object.assign(token.accessToken, {
						client,
						scope: token.scope
					});
					const refreshToken = token.refreshToken ? Object.assign(token.refreshToken, {
						client,
						scope: token.scope
					}) : null;
			
					store.token.access[accessToken.id] = accessToken;
					store.token.refresh[refreshToken.id] = refreshToken;
			
					return true;
				}
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