import express from "express";
import {
	authenticateUser,
	createJWTPayload,
	createJWTHeader,
	handleTokenError,
	renderDashboard,
	renderLogin,
	isTokenExpired,
	setAuthCookie,
} from "../utils/auth.js";
import { generateFlag, randomUUID } from "../utils/crypto.js";
import { signJWT, verifyJWT } from "../utils/jwt.js";

const router = express.Router();
const WEAK_SECRET = "s3cr3t";
const FLAG = generateFlag();
const LOGIN_ACTION = "/weak-secret";

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
	const header = createJWTHeader({
		kid: randomUUID(),
	});

	signJWT({ payload, header }, WEAK_SECRET, "HS256")
		.then((token) => {
			setAuthCookie(res, token);
			console.log("Token created for user:", username);
			res.redirect("/weak-secret/dashboard");
		})
		.catch((err) => {
			console.error("Token creation failed:", err);
			return renderLogin(res, LOGIN_ACTION, "Token creation failed");
		});
});

router.get("/dashboard", (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/weak-secret");
	}

	verifyJWT(token, WEAK_SECRET)
		.then((decoded) => {
			if (isTokenExpired(decoded)) {
				return handleTokenError(res, LOGIN_ACTION, "Token has expired");
			}
			renderDashboard(res, decoded.role, FLAG);
		})
		.catch((err) => {
			return handleTokenError(res, LOGIN_ACTION, err);
		});
});

export default router;
