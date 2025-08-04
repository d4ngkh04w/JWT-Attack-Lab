import express from "express";
import jwt from "json-web-token";
import {
	authenticateUser,
	createJWTPayload,
	handleTokenError,
	renderDashboard,
	renderLogin,
	setAuthCookie,
	isTokenExpired,
	verifyNoneAlgToken,
} from "../utils/auth.js";
import {
	generateFlag,
	generateRandomSecret,
	randomUUID,
} from "../utils/crypto.js";

const router = express.Router();
const SECRET = generateRandomSecret();
const FLAG = generateFlag();
const LOGIN_ACTION = "/alg-none";

const verifyToken = (token, secret, callback) => {
	jwt.decode(secret, token, (err, decoded) => {
		if (!err) return callback(null, decoded);

		const noneDecoded = verifyNoneAlgToken(token);
		if (noneDecoded) return callback(null, noneDecoded);

		callback(err || new Error("Invalid token"));
	});
};

router.get("/", (req, res) => {
	renderLogin(res, LOGIN_ACTION);
});

router.post("/", (req, res) => {
	const { username, password } = req.body;
	const user = authenticateUser(username, password);

	if (!user) {
		return renderLogin(res, LOGIN_ACTION, "Invalid credentials");
	}

	const payload = createJWTPayload(user);
	const header = {
		kid: randomUUID(),
	};
	jwt.encode(SECRET, { payload, header }, "HS256", (err, token) => {
		if (err) {
			return renderLogin(res, LOGIN_ACTION, "Token creation failed");
		}
		console.log("Token: ", token);
		setAuthCookie(res, token);
		res.redirect("/alg-none/dashboard");
	});
});

router.get("/dashboard", (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/alg-none");
	}

	verifyToken(token, SECRET, (err, decoded) => {
		if (err) {
			return handleTokenError(res, LOGIN_ACTION, err);
		}

		if (isTokenExpired(decoded)) {
			return handleTokenError(res, LOGIN_ACTION, "Token has expired");
		}

		renderDashboard(res, decoded.role, FLAG);
	});
});

export default router;
