import { users } from "../data/user.js";

const authenticateUser = (username, password) => {
	return (
		users.find((u) => u.username === username && u.password === password) ||
		null
	);
};

const setAuthCookie = (res, token) => {
	res.cookie("token", token, {
		httpOnly: true,
		maxAge: 30 * 60 * 1000, // 30 minutes
	});
};

const renderLogin = (res, loginAction, error = null) => {
	res.render("login", {
		loginAction,
		error,
	});
};

const renderDashboard = (res, role, flag) => {
	res.render("dashboard", {
		role,
		flag: role === "admin" ? flag : null,
	});
};

const createJWTPayload = (user) => {
	return { role: user.role };
};

const handleTokenError = (res, loginAction, err) => {
	console.error("Token verification failed: ", err);
	renderLogin(res, loginAction, "Invalid token. Please login again.");
};

export {
	authenticateUser,
	setAuthCookie,
	renderLogin,
	renderDashboard,
	createJWTPayload,
	handleTokenError,
};
