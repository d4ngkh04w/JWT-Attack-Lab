import express from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import {
	authenticateUser,
	setAuthCookie,
	renderLogin,
	renderDashboard,
	createJWTPayload,
	handleTokenError,
} from "../utils/auth.js";
import { jwkToPem, generateFlag } from "../utils/crypto.js";
import { publicKey, privateKey } from "../utils/keys.js";

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

	const payload = createJWTPayload(user);
	const token = jwt.sign(payload, privateKey, {
		algorithm: "RS256",
		expiresIn: "30m",
		header: {
			kid: crypto.randomUUID(),
		},
	});

	setAuthCookie(res, token);
	console.log("Token: ", token);
	res.redirect("/jku/dashboard");
});

router.get("/dashboard", async (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/jku");
	}

	const decoded = jwt.decode(token, { complete: true });
	if (!decoded) return res.redirect("/jku");

	let verificationKey = publicKey;

	if (decoded.header.jku) {
		try {
			const jwks = await fetch(decoded.header.jku).then((res) =>
				res.json()
			);
			console.log("Fetched JWKs:", jwks);

			const jwk = jwks.keys.find((k) => k.kid === decoded.header.kid);
			if (!jwk) {
				console.error("JWK not found for kid:", decoded.header.kid);
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

	jwt.verify(
		token,
		verificationKey,
		{ algorithms: ["RS256"] },
		(err, decoded) => {
			if (err) {
				return handleTokenError(res, LOGIN_ACTION, err);
			}

			renderDashboard(res, decoded.role, FLAG);
		}
	);
});

export default router;
