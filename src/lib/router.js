import { getMethod, getPath, normalizeError } from "./http.js";
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

        return await route.handler(event, { params });
      }

      throw notFound(`Route ${method} ${path} not found`);
    } catch (error) {
      return normalizeError(error);
    }
  };
}