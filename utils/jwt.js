import jwt from "json-web-token";
import { promisify } from "util";

const jwtEncode = promisify(jwt.encode);
const jwtDecode = promisify(jwt.decode);

const signJWT = async (data, key, algorithm = "RS256") => {
	if (!data || !key) {
		throw new Error("Data and key are required for JWT signing");
	}

	if (typeof data !== "object") {
		throw new Error("Data must be an object");
	}

	if (typeof key !== "string") {
		throw new Error("Key must be a string");
	}

	return await jwtEncode(key, data, algorithm);
};

const verifyJWT = async (token, key) => {
	if (!token || !key) {
		throw new Error("Token and key are required for JWT verification");
	}

	if (typeof token !== "string") {
		throw new Error("Token must be a string");
	}

	if (typeof key !== "string") {
		throw new Error("Key must be a string");
	}

	return await jwtDecode(key, token);
};

export { signJWT, verifyJWT };
