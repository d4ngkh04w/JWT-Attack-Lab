import express from "express";
import {
	authenticateUser,
	setAuthCookie,
	renderLogin,
	renderDashboard,
	createJWTPayload,
	handleTokenError,
	createJWTHeader,
	isTokenExpired,
} from "../utils/auth.js";
import { generateFlag, randomUUID } from "../utils/crypto.js";
import { PUBLIC_KEY, PRIVATE_KEY } from "../utils/keys.js";
import { signJWT, verifyJWT } from "../utils/jwt.js";

const router = express.Router();
const FLAG = generateFlag();
const LOGIN_ACTION = "/key-confusion";

router.get("/", (req, res) => {
	renderLogin(res, LOGIN_ACTION);
});

router.post("/", async (req, res) => {
	const { username, password } = req.body;
	const user = authenticateUser(username, password);

	if (!user) {
		return renderLogin(res, LOGIN_ACTION, "Invalid credentials");
	}

	const payload = createJWTPayload(user);
	const header = createJWTHeader({
		kid: randomUUID(),
	});

	signJWT({ payload, header }, PRIVATE_KEY, "RS256")
		.then((token) => {
			setAuthCookie(res, token);
			console.log("Token created for user:", username);
			res.redirect("/key-confusion/dashboard");
		})
		.catch((err) => {
			console.error("Token creation failed:", err);
			return renderLogin(res, LOGIN_ACTION, "Token creation failed");
		});
});

router.get("/dashboard", async (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/key-confusion");
	}

	verifyJWT(token, PUBLIC_KEY)
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
