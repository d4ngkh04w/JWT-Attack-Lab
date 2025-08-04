import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";

import weakSecret from "./routes/weak-secret.js";
import algNone from "./routes/alg-none.js";
import jku from "./routes/jku.js";
import jwk from "./routes/jwk.js";
import kid from "./routes/kid.js";
import keyConfusion from "./routes/key-confusion.js";
import { PUBLIC_KEY } from "./utils/keys.js";

const app = express();

const PORT = 8888;

app.set("view engine", "ejs");

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(cookieParser());
app.use((req, res, next) => {
	res.set("Cache-Control", "no-store, no-cache");
	next();
});

const base64urlEncode = (data) => {
	if (!data) {
		throw new Error("Data is required for encoding");
	}
	return data.toString("base64url").replace(/=+$/, "");
};

app.get("/", (req, res) => {
	try {
		res.clearCookie("token");
		res.render("index");
	} catch (error) {
		console.error("Error rendering index page:", error);
		res.status(500).send("Internal Server Error");
	}
});

app.get("/jwks.json", (req, res) => {
	try {
		if (!PUBLIC_KEY) {
			console.error("Public key not available");
			return res.status(500).json({ error: "Public key not available" });
		}

		const publicKeyObj = crypto.createPublicKey(PUBLIC_KEY);
		const publicKeyDetails = publicKeyObj.export({ format: "jwk" });

		console.log("Public Key Details:", publicKeyDetails);

		const jwks = {
			kty: publicKeyDetails.kty || "RSA",
			kid: publicKeyDetails.kid || crypto.randomUUID(),
			n: base64urlEncode(Buffer.from(publicKeyDetails.n, "base64")),
			e: base64urlEncode(Buffer.from(publicKeyDetails.e, "base64")),
		};

		res.json({ keys: [jwks] });
	} catch (err) {
		console.error("Error generating JWKs:", err);
		return res.status(500).json({ error: "Error generating JWKs" });
	}
});

app.use("/weak-secret", weakSecret);
app.use("/alg-none", algNone);
app.use("/jku", jku);
app.use("/jwk", jwk);
app.use("/kid", kid);
app.use("/key-confusion", keyConfusion);

app.use((req, res) => {
	res.status(404).json({ error: "Not Found" });
});

app.use((err, req, res, next) => {
	console.error("Unhandled error:", err);
	res.status(500).json({ error: "Internal Server Error" });
});

app.listen(PORT, () => {
	console.log(`JWT Lab running at http://127.0.0.1:${PORT}`);
});
