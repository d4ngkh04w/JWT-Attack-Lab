import crypto from "crypto";

const jwkToPem = (jwk) => {
	try {
		if (!jwk || typeof jwk !== "object") {
			throw new Error("Invalid JWK object provided");
		}

		const keyObject = crypto.createPublicKey({
			key: jwk,
			format: "jwk",
		});

		return keyObject.export({
			type: "spki",
			format: "pem",
		});
	} catch (error) {
		console.error("Error converting JWK to PEM:", error);
		throw new Error(`Failed to convert JWK to PEM: ${error.message}`);
	}
};

const generateRandomSecret = (length = 16) => {
	if (typeof length !== "number" || length <= 0) {
		throw new Error("Length must be a positive number");
	}

	return crypto.randomBytes(length).toString("hex");
};

const randomUUID = () => {
	return crypto.randomUUID();
};

const generateFlag = () => `FLAG{${crypto.randomBytes(16).toString("hex")}}`;

export { jwkToPem, generateRandomSecret, randomUUID, generateFlag };
