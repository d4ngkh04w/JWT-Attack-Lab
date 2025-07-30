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
import { jwkToPem, generateFlag, randomUUID } from "../utils/crypto.js";
import { publicKey, privateKey } from "../utils/keys.js";

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

	const payload = createJWTPayload(user);
	const token = jwt.sign(payload, privateKey, {
		algorithm: "RS256",
		expiresIn: "30m",
		header: {
			kid: randomUUID(),
		},
	});

	setAuthCookie(res, token);
	console.log("Token: ", token);
	res.redirect("/jwk/dashboard");
});

router.get("/dashboard", (req, res) => {
	const token = req.cookies.token;

	if (!token) {
		return res.redirect("/jwk");
	}

	// Giải mã token mà không xác thực signature
	const decoded = jwt.decode(token, { complete: true });

	if (!decoded) {
		throw new Error("Invalid token");
	}

	let verificationKey = publicKey;

	if (decoded.header.jwk) {
		// Chuyển đổi JWK thành PEM format
		const jwk = decoded.header.jwk;
		console.log("Using JWK:\n", jwk);

		if (jwk.kty === "RSA") {
			verificationKey = jwkToPem(jwk);
		} else {
			console.error("Unsupported JWK type:", jwk.kty);
			return res.redirect("/jwk");
		}
	}

	// Xác thực token với public key
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
