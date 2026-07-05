import { getMethod, getPath, normalizeError, resolveAllowedOrigin } from "./http.js";
import { notFound } from "./errors.js";

function compileRoute(pathTemplate) {
  const paramNames = [];
  const pattern = pathTemplate.replace(/:[^/]+/g, (segment) => {
    paramNames.push(segment.slice(1));
    return "([^/]+)";
  });

  return {
    regex: new RegExp(`^${pattern}$`),
    paramNames,
  };
}

function withCorsOrigin(response, event) {
  const origin = resolveAllowedOrigin(event);
  return {
    ...response,
    headers: {
      ...response?.headers,
      "Access-Control-Allow-Origin": origin,
      Vary: "Origin",
    },
  };
}

export function createRouter(routes) {
  const compiled = routes.map((route) => ({
    ...route,
    ...compileRoute(route.path),
  }));

  return async function routeEvent(event) {
    try {
      const method = getMethod(event).toUpperCase();
      const path = getPath(event);

      for (const route of compiled) {
        if (route.method !== method) {
          continue;
        }

        const match = path.match(route.regex);
        if (!match) {
          continue;
        }

        const params = {};
        route.paramNames.forEach((name, index) => {
          params[name] = decodeURIComponent(match[index + 1]);
        });

        const response = await route.handler(event, { params });
        return withCorsOrigin(response, event);
      }

      throw notFound(`Route ${method} ${path} not found`);
    } catch (error) {
      return withCorsOrigin(normalizeError(error), event);
    }
  };
}
