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
			saveToken: _saveToken = finalOptions.saveToken
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

		finalOptions.saveToken = _saveToken;
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
		saveToken(token, client) {
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
	};
}