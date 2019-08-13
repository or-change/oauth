module.exports = function Request(options) {
	const { headers, method, query } = options;

	if(!headers || !method || !query) {
		throw new Error('Missing parameter');
	}

	return {
		headers, method, query,
		body: options.body || {},
	};
};