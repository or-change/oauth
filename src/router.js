'use strict';

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'];

function Context(req, res, requestBody, queryClient) {
	const url = new URL(req.url, 'http://example');
	const query = {};
	
	url.searchParams.forEach((value, key) => {
		query[key] = value;
	});

	return {
		req,
		res,
		query: Object.freeze(query),
		request: {
			body: requestBody
		},
		queryClient
	};
}

function DefaultRequestBodyGetter(req) {
	return function getBody() {
		const chunks = [];

		return new Promise((resolve, reject) => {
			req
				.on('error', error => reject(error))
				.on('data', chunk => chunks.push(chunk))
				.on('end', () => {
					const length = chunks.reduce((length, chunk) => length += chunk.length, 0);
					const data = Buffer.concat(chunks, length).toString();
					const search = new URLSearchParams(data);
					const body = {};

					search.forEach((value, key) => body[key] = value);

					resolve(body);
				});
		});
	};
}

module.exports = function Router(prefix, queryClient) {
	const store = [];
	const router = {
		callback() {
			return async function handlerWrap(req, res, bodyGetter = {}) {
				const {
					getBody = DefaultRequestBodyGetter(req)
				} = bodyGetter;

				const matched = store.find(options => {
					return options.method === req.method &&
						req.url.indexOf(options.path) !== -1;
				});
	
				if (matched) {
					try {
						await matched.handler(Context(req, res, await getBody(), queryClient));
					} catch (error) {
						res.statusCode = 500;
						res.end(JSON.stringify(error.message));
					}
				}
			};
		}
	};

	METHODS.forEach(name => {
		router[name.toLowerCase()] = function createRouterOptions(path, handler) {
			store.push({
				method: name,
				path: `${prefix}${path}`,
				handler
			});
		};
	});

	return router;
};