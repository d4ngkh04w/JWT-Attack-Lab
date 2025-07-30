import express from "express";
import jwt from "jsonwebtoken";
import {
	authenticateUser,
	createJWTPayload,
	handleTokenError,
	renderDashboard,
	renderLogin,
	setAuthCookie,
} from "../utils/auth.js";
import { generateFlag, randomUUID } from "../utils/crypto.js";

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
	const token = jwt.sign(payload, WEAK_SECRET, {
		expiresIn: "30m",
		header: {
			kid: randomUUID(),
		},
	});
	console.log("Token: ", token);

	setAuthCookie(res, token);
	res.redirect("/weak-secret/dashboard");
});

router.get("/dashboard", (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/weak-secret");
	}

	jwt.verify(
		token,
		WEAK_SECRET,
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
