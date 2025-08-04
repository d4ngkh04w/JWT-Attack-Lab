import express from "express";
import {
	authenticateUser,
	setAuthCookie,
	renderLogin,
	renderDashboard,
	createJWTPayload,
	handleTokenError,
	parseJWTHeader,
	createJWTHeader,
	isTokenExpired,
} from "../utils/auth.js";
import { jwkToPem, generateFlag, randomUUID } from "../utils/crypto.js";
import { PUBLIC_KEY, PRIVATE_KEY } from "../utils/keys.js";
import { signJWT, verifyJWT } from "../utils/jwt.js";

const router = express.Router();
const FLAG = generateFlag();
const LOGIN_ACTION = "/jwk";

router.get("/", (req, res) => {
	renderLogin(res, LOGIN_ACTION);
});

router.post("/", (req, res) => {
	const { username, password } = req.body;

	const user = authenticateUser(username, password);
	if (!user) {
		return renderLogin(res, LOGIN_ACTION, "Invalid credentials");
	}

	if (!PRIVATE_KEY) {
		return renderLogin(res, LOGIN_ACTION, "Server configuration error");
	}

	const payload = createJWTPayload(user);
	const header = createJWTHeader({
		kid: randomUUID(),
	});

	signJWT({ payload, header }, PRIVATE_KEY, "RS256")
		.then((token) => {
			setAuthCookie(res, token);
			console.log("Token created for user:", user.username);
			res.redirect("/jwk/dashboard");
		})
		.catch((err) => {
			console.error("Token creation failed:", err);
			return renderLogin(res, LOGIN_ACTION, "Token creation failed");
		});
});

router.get("/dashboard", (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/jwk");
	}

	const header = parseJWTHeader(token);
	if (!header) {
		console.error("Invalid token header");
		return res.redirect("/jwk");
	}

	if (header.alg !== "RS256") {
		console.error("Invalid algorithm:", header.alg);
		return res.redirect("/jwk");
	}

	let verificationKey = PUBLIC_KEY;

	if (header.jwk) {
		try {
			const jwk = header.jwk;
			console.log("Using JWK from header:", jwk);

			if (jwk.kty === "RSA") {
				verificationKey = jwkToPem(jwk);
				console.log("Converted JWK to PEM successfully");
			} else {
				console.error("Unsupported JWK type:", jwk.kty);
				return res.redirect("/jwk");
			}
		} catch (jwkError) {
			console.error("Error processing JWK:", jwkError);
			return res.redirect("/jwk");
		}
	}

	verifyJWT(token, verificationKey)
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
