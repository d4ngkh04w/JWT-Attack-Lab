import express from "express";
import cookieParser from "cookie-parser";

import weakSecret from "./routes/weak-secret.js";
import algNone from "./routes/alg-none.js";
import jku from "./routes/jku.js";
import jwk from "./routes/jwk.js";
import kid from "./routes/kid.js";

const app = express();
const PORT = 8888;
app.set("view engine", "ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use("/weak-secret", weakSecret);
app.use("/alg-none", algNone);
app.use("/jku", jku);
app.use("/jwk", jwk);
app.use("/kid", kid);

app.get("/", (req, res) => {
	res.clearCookie("token");
	res.render("index");
});

app.listen(PORT, () => {
	console.log(`JWT Lab running at http://127.0.0.1:${PORT}`);
});
