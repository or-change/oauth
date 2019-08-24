const Ajv = require('ajv');
const ajv = new Ajv;
require('ajv-keywords')(ajv, ['instanceof']);

module.exports = function validator(schema, options) {
	const validate = ajv.compile(schema);
	const valid = validate(options);

	if (!valid) {
		validate.errors.forEach(error => {
			console.log(error);
		});

		throw new Error(JSON.stringify(validate.errors));
	}

	return true;
};