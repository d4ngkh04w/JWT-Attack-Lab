import fs from "fs";

const loadKeys = () => {
	try {
		return {
			publicKey: fs.readFileSync("./keys/public.pem", "utf8"),
			privateKey: fs.readFileSync("./keys/private.pem", "utf8"),
		};
	} catch (error) {
		console.error("Error loading keys:", error);
		return { publicKey: null, privateKey: null };
	}
};

const loadSecret = (file = "secret.key") => {
	try {
		if (!fs.existsSync(`./keys/${file}`)) {
			console.error(`Key file ${file} does not exist.`);
			return null;
		}
		return fs.readFileSync(`./keys/${file}`, "utf8").trim() || "";
	} catch (error) {
		console.error("Error loading secret key:", error);
		return null;
	}
};

const { publicKey, privateKey } = loadKeys();

export { publicKey, privateKey, loadSecret };
