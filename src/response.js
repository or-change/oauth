module.exports = function Response(options) {
	return {
		body: options.body || {},
		headers: options.headers || {},
		status: 200,
		set(field, value) {
			return this.headers[field.toLowerCase()] = value;
		},
		redirect(url) {
			this.set('Location', url);
			this.status = 302;
		}
	};
};