import fs from "fs";

const loadKeys = async () => {
	try {
		const [publicKey, privateKey] = await Promise.all([
			fs.promises.readFile("./keys/public.pem", "utf8"),
			fs.promises.readFile("./keys/private.pem", "utf8"),
		]);

		return {
			publicKey: publicKey.trim(),
			privateKey: privateKey.trim(),
		};
	} catch (error) {
		console.error("Error loading keys:", error);
		return { publicKey: null, privateKey: null };
	}
};

const loadSecret = async (file = "secret.key") => {
	try {
		const filePath = `./keys/${file}`;

		await fs.promises.access(filePath, fs.constants.F_OK);

		const content = await fs.promises.readFile(filePath, "utf8");
		return content.trim() || "";
	} catch (error) {
		if (error.code === "ENOENT") {
			console.error(`Key file ${file} does not exist.`);
		} else {
			console.error("Error loading secret key:", error);
		}
		return null;
	}
};

const { publicKey, privateKey } = await loadKeys();

export { publicKey as PUBLIC_KEY, privateKey as PRIVATE_KEY, loadSecret };
