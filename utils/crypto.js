import crypto from "crypto";

const jwkToPem = (jwk) => {
	const keyObject = crypto.createPublicKey({
		key: jwk,
		format: "jwk",
	});
	return keyObject.export({
		type: "spki",
		format: "pem",
	});
};

const generateRandomSecret = (length = 16) => {
	return crypto.randomBytes(length).toString("hex");
};

const randomUUID = () => {
	return crypto.randomUUID();
};

const generateFlag = () => `FLAG{${crypto.randomBytes(16).toString("hex")}}`;

export { jwkToPem, generateRandomSecret, randomUUID, generateFlag };
