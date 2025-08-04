import { users } from "../data/user.js";

const authenticateUser = (username, password) => {
	if (
		!username ||
		!password ||
		typeof username !== "string" ||
		typeof password !== "string"
	) {
		return null;
	}

	return (
		users.find((u) => u.username === username && u.password === password) ||
		null
	);
};

const setAuthCookie = (res, token) => {
	if (!token || typeof token !== "string") {
		throw new Error("Invalid token provided");
	}

	res.cookie("token", token, {
		httpOnly: true,
		maxAge: 30 * 60 * 1000, // 30 minutes
	});
};

const renderLogin = (res, loginAction, error = null) => {
	res.render("login", {
		loginAction,
		error,
	});
};

const renderDashboard = (res, role, flag) => {
	res.render("dashboard", {
		role,
		flag: role === "admin" ? flag : null,
	});
};

const createJWTPayload = (user) => {
	if (!user || !user.role) {
		throw new Error("Invalid user object");
	}

	return {
		role: user.role,
		aud: "jwt-attack-lab",
		exp: Math.floor(Date.now() / 1000) + 30 * 60, // 30 minutes
	};
};

const isTokenExpired = (decoded) => {
	if (!decoded || typeof decoded.exp !== "number") {
		return true;
	}

	const now = Math.floor(Date.now() / 1000);
	return decoded.exp < now;
};

const createJWTHeader = ({ kid, jwk, jku } = {}) => {
	const header = {};

	if (kid) header.kid = kid;
	if (jwk) header.jwk = jwk;
	if (jku) header.jku = jku;

	return header;
};

const handleTokenError = (res, loginAction, err) => {
	console.error("Token verification failed:", err);
	renderLogin(res, loginAction, "Invalid token. Please login again.");
};

const parseJWTHeader = (token) => {
	try {
		if (!token || typeof token !== "string") {
			return null;
		}

		const parts = token.split(".");
		if (parts.length !== 3) {
			return null;
		}

		const header = JSON.parse(Buffer.from(parts[0], "base64").toString());
		return header;
	} catch (err) {
		console.error("Error parsing JWT header:", err);
		return null;
	}
};

const createNoneAlgToken = (payload) => {
	if (!payload || typeof payload !== "object") {
		throw new Error("Invalid payload provided");
	}

	const header = { alg: "none", typ: "JWT" };
	const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
		"base64url"
	);
	const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
		"base64url"
	);

	return `${encodedHeader}.${encodedPayload}.`;
};

const verifyNoneAlgToken = (token) => {
	try {
		if (!token || typeof token !== "string") {
			return null;
		}

		const parts = token.split(".");
		if (parts.length !== 3 || parts[2] !== "") {
			return null;
		}

		const header = JSON.parse(
			Buffer.from(parts[0], "base64url").toString()
		);
		if (header.alg !== "none") {
			return null;
		}

		const payload = JSON.parse(
			Buffer.from(parts[1], "base64url").toString()
		);
		return payload;
	} catch (err) {
		console.error("Error verifying none algorithm token:", err);
		return null;
	}
};

export {
	authenticateUser,
	setAuthCookie,
	renderLogin,
	renderDashboard,
	createJWTPayload,
	createJWTHeader,
	handleTokenError,
	parseJWTHeader,
	createNoneAlgToken,
	verifyNoneAlgToken,
	isTokenExpired,
};
