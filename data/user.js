import { randomBytes } from "crypto";

export const users = [
	{
		username: "guest",
		password: "guest",
		role: "guest",
	},
	{
		username: "admin",
		password: randomBytes(32).toString("hex"),
		role: "admin",
	},
];
