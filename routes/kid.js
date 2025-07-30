import express from "express";
import jwt from "jsonwebtoken";

import {
	authenticateUser,
	setAuthCookie,
	renderLogin,
	renderDashboard,
	createJWTPayload,
	handleTokenError,
} from "../utils/auth.js";
import { generateFlag } from "../utils/crypto.js";
import { loadSecret } from "../utils/keys.js";

const router = express.Router();
const FLAG = generateFlag();
const LOGIN_ACTION = "/kid";
const SECRET = loadSecret();

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

	const token = jwt.sign(payload, SECRET, {
		algorithm: "HS256",
		expiresIn: "30m",
		header: {
			kid: "secret.key",
		},
	});

	setAuthCookie(res, token);
	console.log("Token: ", token);
	res.redirect("/kid/dashboard");
});

router.get("/dashboard", (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/kid");
	}

	const decoded = jwt.decode(token, { complete: true });
	if (!decoded) {
		return res.redirect("/kid");
	}

	let verificationKey = SECRET;

	if (decoded.header.kid) {
		verificationKey = loadSecret(decoded.header.kid);
		console.log("Verification Key: ", verificationKey);
		if (verificationKey === null) {
			console.error(
				"Verification key not found for KID:",
				decoded.header.kid
			);
			return res.redirect("/kid");
		}
	}

	jwt.verify(
		token,
		verificationKey,
		{ algorithms: ["HS256"] },
		(err, decoded) => {
			if (err) {
				return handleTokenError(res, LOGIN_ACTION, err);
			}

			renderDashboard(res, decoded.role, FLAG);
		}
	);
});

export default router;
