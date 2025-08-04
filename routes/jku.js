import express from "express";
import crypto from "crypto";
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
import { jwkToPem, generateFlag } from "../utils/crypto.js";
import { PUBLIC_KEY, PRIVATE_KEY } from "../utils/keys.js";
import { signJWT, verifyJWT } from "../utils/jwt.js";

const router = express.Router();
const FLAG = generateFlag();
const LOGIN_ACTION = "/jku";

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
		kid: crypto.randomUUID(),
	});

	signJWT({ payload, header }, PRIVATE_KEY, "RS256")
		.then((token) => {
			setAuthCookie(res, token);
			console.log("Token: ", token);
			res.redirect("/jku/dashboard");
		})
		.catch((err) => {
			console.error("Token creation failed:", err);
			return renderLogin(res, LOGIN_ACTION, "Token creation failed");
		});
});

router.get("/dashboard", async (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/jku");
	}

	const header = parseJWTHeader(token);

	if (!header) {
		return res.redirect("/jku");
	}

	if (header.alg !== "RS256") {
		return res.redirect("/jku");
	}

	let verificationKey = PUBLIC_KEY;

	if (header.jku) {
		try {
			const jwks = await fetch(header.jku).then((res) => res.json());
			console.log("Fetched JWKs:", jwks);

			const jwk = jwks.keys.find((k) => k.kid === header.kid);
			if (!jwk) {
				console.error("JWK not found for kid:", header.kid);
				return res.redirect("/jku");
			}

			if (jwk.kty === "RSA") {
				verificationKey = jwkToPem(jwk);
			} else {
				console.error("Unsupported JWK type:", jwk.kty);
				return res.redirect("/jku");
			}
		} catch (error) {
			console.error("Error fetching JWKs:", error);
			return res.redirect("/jku");
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
