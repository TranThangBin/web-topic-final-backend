const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const path = require("path");
const mongodb = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const PORT = process.env.PORT;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(",");
const MODE = process.env.MODE;
const SIGNING_KEY = process.env.SIGNING_KEY;
const ACCESS_TOKEN_DURATION_IN_HOUR = process.env.ACCESS_TOKEN_DURATION_IN_HOUR;
const REFRESH_TOKEN_DURATION_IN_HOUR =
	process.env.REFRESH_TOKEN_DURATION_IN_HOUR;
const WORK_FACTOR = process.env.WORK_FACTOR;
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_APPNAME = process.env.MONGODB_APPNAME;
const MONGODB_USERNAME = process.env.MONGODB_USERNAME;
const MONGODB_PASSWORD = process.env.MONGODB_PASSWORD;
const MONGODB_DATABASE = process.env.MONGODB_DATABASE;
const MONGODB_GAMES_COLLECTION = process.env.MONGODB_GAMES_COLLECTION;
const MONGODB_USERS_COLLECTION = process.env.MONGODB_USERS_COLLECTION;

const categories = new Map([
	["roleplay", "RP"],
	["moba", "MB"],
	["sandbox", "SB"],
]);

const missingNameError = new Error("the field name is require but get nothing");
const missingAuthorError = new Error(
	"the field author is require but get nothing",
);
const missingReleaseDateError = new Error(
	"the field releaseDate is require but get nothing",
);
const invalidCategoryError = new Error(
	"the category provided is not avaiable please try these categories: " +
		Array.from(categories.keys()).toString(),
);
const gameNotFoundError = new Error("no game match the query");

const missingUsernameError = new Error(
	"the field username is require but get nothing",
);
const missingPasswordError = new Error(
	"the field password is require but get nothing",
);
const mismatchedPasswordError = new Error(
	"confirmPassword does not match password",
);
const usernameAlreadyUsedError = new Error(
	"the username has been used by someone else",
);
const authenticationError = new Error("username or password is incorrect");
const unauthorizedError = new Error("you haven't logged in yet");

const mongoClient = new mongodb.MongoClient(MONGODB_URI, {
	appName: MONGODB_APPNAME,
	auth: {
		username: MONGODB_USERNAME,
		password: MONGODB_PASSWORD,
	},
});
const app = express();
const gameRoute = express.Router();
const authRoute = express.Router();

if (MODE === "dev") {
	gameRoute.get("/dev/all", handleGetAllGames);
	gameRoute.post("/dev/new", handleInsertGame);
	gameRoute.delete("/dev/delete/:id", handleDeleteGame);
	gameRoute.patch("/dev/update/:id", handleUpdateGame);

	authRoute.post("/dev/hash", handleHashPassword, (req, res) => {
		res.end(req.hashedPass);
	});
	authRoute.post(
		"/dev/token/sign",
		(req, _, next) => {
			const { id, username } = req.body || {};
			req.payload = { id, username };
			req.issueNew = true;
			next();
		},
		handleSigningToken,
		(req, res) => {
			res.json({
				accessToken: req.accessToken,
				refreshToken: req.refreshToken,
			});
		},
	);
	authRoute.post(
		"/dev/token/decode",
		(req, _, next) => {
			const { accessToken, refreshToken } = req.body || {};
			req.tokens = { accessToken, refreshToken };
			next();
		},
		handleDecodeToken,
		handleSigningToken,
		(req, res) => {
			res.json({
				accessTokenPayload: req.accessTokenPayload,
				refreshTokenPayload: req.refreshTokenPayload,
			});
		},
	);

	authRoute.post(
		"/dev/login",
		handleAuthorizeUser,
		handleSigningToken,
		(req, res) => {
			const accessTokenCookieExp = new Date(Date.now() + 1000 * 60 * 2);
			const refreshTokenCookieExp = new Date(Date.now() + 1000 * 60 * 2);
			res.status(200)
				.cookie("accessToken", req.accessToken, {
					expires: accessTokenCookieExp,
				})
				.cookie("refreshToken", req.refreshToken, {
					expires: refreshTokenCookieExp,
				})
				.end();
		},
	);

	authRoute.get(
		"/dev/authorize",
		handleTokensContext,
		handleDecodeToken,
		handleSigningToken,
		(_, res) => {
			res.status(200).end();
		},
	);
}

authRoute.post(
	"/register",
	(req, _, next) => {
		const { username, password, confirmPassword } = req.body || {};
		if (!username) {
			next(missingUsernameError);
			return;
		}
		if (!password) {
			next(missingPasswordError);
			return;
		}
		if (password !== confirmPassword) {
			next(mismatchedPasswordError);
			return;
		}
		next();
	},
	handleHashPassword,
	async (req, res, next) => {
		const user = { username: req.body.username, password: req.hashedPass };
		try {
			const expectedNullUser = await mongoClient
				.db(MONGODB_DATABASE)
				.collection(MONGODB_USERS_COLLECTION)
				.findOne({ username: user.username });

			if (expectedNullUser !== null) {
				next(usernameAlreadyUsedError);
				return;
			}

			const lastUser = await mongoClient
				.db(MONGODB_DATABASE)
				.collection(MONGODB_USERS_COLLECTION)
				.findOne(
					{},
					{ projection: { _id: false, id: true }, sort: { _id: -1 } },
				);

			if (lastUser === null) {
				user.id = newUserId(0);
			} else {
				user.id = newUserId(parseInt(lastUser.id.slice(-4)));
			}

			await mongoClient
				.db(MONGODB_DATABASE)
				.collection(MONGODB_USERS_COLLECTION)
				.insertOne(user);

			res.status(200).end();
		} catch (err) {
			next(err);
		}
	},
);

authRoute.post(
	"/login",
	handleAuthorizeUser,
	handleSigningToken,
	(req, res) => {
		const accessTokenCookieExp = new Date(
			Date.now() +
				1000 * 60 * 60 * ACCESS_TOKEN_DURATION_IN_HOUR +
				1000 * 60,
		);
		const refreshTokenCookieExp = new Date(
			Date.now() +
				1000 * 60 * 60 * REFRESH_TOKEN_DURATION_IN_HOUR +
				1000 * 60,
		);
		res.status(200)
			.cookie("accessToken", req.accessToken, {
				expires: accessTokenCookieExp,
				httpOnly: true,
			})
			.cookie("refreshToken", req.refreshToken, {
				expires: refreshTokenCookieExp,
				httpOnly: true,
			})
			.end();
	},
);

gameRoute.use(handleTokensContext, handleDecodeToken, handleSigningToken);
gameRoute.get("/all", handleGetAllGames);
gameRoute.post("/new", handleInsertGame);
gameRoute.delete("/delete/:id", handleDeleteGame);
gameRoute.patch("/update/:id", handleUpdateGame);

app.use((req, _, next) => {
	console.log(req.method, req.path);
	next();
});
app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.static(path.join(__dirname, "..", "public")));
app.use(express.json());
app.use(express.urlencoded());
app.use(cookieParser());
app.use("/game", gameRoute);
app.use("/auth", authRoute);
app.use((err, _, res, __) => {
	if (err === gameNotFoundError) {
		console.log(err, "this is a user error");
		res.status(404).json({ message: err.message });
		return;
	}
	if (
		err === missingNameError ||
		err === missingAuthorError ||
		err === missingReleaseDateError ||
		err === invalidCategoryError ||
		err === missingUsernameError ||
		err === missingPasswordError ||
		err === mismatchedPasswordError ||
		err === usernameAlreadyUsedError
	) {
		console.log(err, "this is a user error");
		res.status(400).json({ message: err.message });
		return;
	}
	console.error(err, "this is a system error");
	res.status(500).json({ message: "something went wrong with the server" });
});

mongoClient
	.connect()
	.then(() => {
		console.log("successfully connected to the database");
		app.listen(PORT, (err) => {
			if (err !== undefined) {
				console.error(err, "failed to start the server");
				process.exit(1);
			} else {
				console.log(`listening at http://127.0.0.1:${PORT}`);
			}
		});
	})
	.catch((err) => {
		console.error(err, "failed to connect to the database");
		process.exit(1);
	});

async function handleGetAllGames(_, res) {
	try {
		const games = await mongoClient
			.db(MONGODB_DATABASE)
			.collection(MONGODB_GAMES_COLLECTION)
			.find({}, { projection: { _id: false } })
			.toArray();

		res.json(games);
	} catch (err) {
		next(err);
	}
}

async function handleInsertGame(req, res, next) {
	const { name, releaseDate, description, price, author, category } =
		req.body || {};
	const newGame = { name, releaseDate: new Date(releaseDate), author };
	if (!newGame.name) {
		next(missingNameError);
		return;
	}
	if (!newGame.author) {
		next(missingAuthorError);
		return;
	}
	if (!newGame.releaseDate.getTime()) {
		next(missingReleaseDateError);
		return;
	}
	if (!categories.has(category)) {
		next(invalidCategoryError);
		return;
	}
	if (description) {
		newGame.description = description;
	}
	if (price) {
		newGame.price = parseInt(price) || 0;
	}

	try {
		const lastGame = await mongoClient
			.db(MONGODB_DATABASE)
			.collection(MONGODB_GAMES_COLLECTION)
			.findOne(
				{},
				{ projection: { _id: false, id: true }, sort: { _id: -1 } },
			);

		if (lastGame === null) {
			newGame.id = newGameId(0, category);
		} else {
			newGame.id = newGameId(parseInt(lastGame.id.slice(-4)), category);
		}

		await mongoClient
			.db(MONGODB_DATABASE)
			.collection(MONGODB_GAMES_COLLECTION)
			.insertOne(newGame);

		const { _id, ...game } = newGame;

		res.json(game);
	} catch (err) {
		next(err);
	}
}

async function handleDeleteGame(req, res, next) {
	const id = req.params.id;
	try {
		const result = await mongoClient
			.db(MONGODB_DATABASE)
			.collection(MONGODB_GAMES_COLLECTION)
			.deleteOne({ id });

		if (result.deletedCount <= 0) {
			next(gameNotFoundError);
			return;
		}

		res.status(200).end();
	} catch (err) {
		next(err);
	}
}

async function handleUpdateGame(req, res, next) {
	const id = req.params.id;
	const { name, releaseDate, description, price, author } = req.body || {};
	const newGame = {};
	if (name !== undefined) {
		if (name === "") {
			next(missingNameError);
			return;
		}
		newGame.name = name;
	}
	if (author !== undefined) {
		if (author === "") {
			next(missingAuthorError);
			return;
		}
		newGame.author = author;
	}
	if (releaseDate !== undefined) {
		const _releaseDate = new Date(releaseDate);
		if (_releaseDate.getTime()) {
			next(missingReleaseDateError);
			return;
		}
		newGame.releaseDate = _releaseDate;
	}
	if (description) {
		newGame.description = description;
	}
	if (price) {
		newGame.price = parseInt(price) || 0;
	}
	try {
		const result = await mongoClient
			.db(MONGODB_DATABASE)
			.collection(MONGODB_GAMES_COLLECTION)
			.updateOne({ id }, { $set: { ...newGame } });
		if (result.matchedCount <= 0) {
			next(gameNotFoundError);
			return;
		}
		if (result.modifiedCount <= 0) {
			res.status(304).end();
			return;
		}
		const { _id, ...game } = newGame;
		res.json(game);
	} catch (err) {
		next(err);
	}
}

async function handleHashPassword(req, _, next) {
	const { password } = req.body || {};
	try {
		req.hashedPass = await bcrypt.hash(password, parseInt(WORK_FACTOR));
		next();
	} catch (err) {
		next(err);
	}
}

async function handleAuthorizeUser(req, _, next) {
	const { username, password } = req.body;

	try {
		const user = await mongoClient
			.db(MONGODB_DATABASE)
			.collection(MONGODB_USERS_COLLECTION)
			.findOne({ username });

		if (user === null) {
			next(authenticationError);
			return;
		}

		const matched = await bcrypt.compare(password, user.password);
		if (!matched) {
			next(authenticationError);
			return;
		}

		req.payload = {
			id: user.id,
			username: user.username,
		};

		next();
	} catch (err) {
		next(err);
	}
}

function handleSigningToken(req, _, next) {
	if (!req.issueNew) {
		next();
	}

	try {
		req.accessToken = jwt.sign(req.payload, SIGNING_KEY, {
			expiresIn: 60 * 60 * parseInt(ACCESS_TOKEN_DURATION_IN_HOUR),
		});
		req.refreshToken = jwt.sign(req.payload, SIGNING_KEY, {
			expiresIn: 60 * 60 * parseInt(REFRESH_TOKEN_DURATION_IN_HOUR),
		});
		next();
	} catch (err) {
		next(err);
	}
}

function handleTokensContext(req, _, next) {
	const { accessToken, refreshToken } = req.cookies || {};
	if (!accessToken && !refreshToken) {
		next(unauthorizedError);
		return;
	}
	req.tokens = {
		accessToken,
		refreshToken,
	};
	next();
}

function handleDecodeToken(req, _, next) {
	const accessTokenPayload = jwt.decode(req.tokens.accessToken);
	const refreshTokenPayload = jwt.decode(req.tokens.refreshToken);

	const now = new Date().getUTCSeconds();

	if (!accessTokenPayload || accessTokenPayload.exp < now) {
		if (!refreshTokenPayload || refreshTokenPayload.exp < now) {
			next(unauthorizedError);
			return;
		}

		const { id, username } = refreshTokenPayload;
		req.payload = { id, username };
		req.issueNew = true;
	} else {
		const { id, username } = accessTokenPayload;
		req.payload = { id, username };
	}

	next();
}

function newGameId(prevIdx, category) {
	let idx = 1;
	if (prevIdx > 0) {
		idx = prevIdx + 1;
	}
	return "GAME" + categories.get(category) + idx.toString().padStart(4, "0");
}

function newUserId(prevIdx) {
	let idx = 1;
	if (prevIdx > 0) {
		idx = prevIdx + 1;
	}
	return "USR" + idx.toString().padStart(4, "0");
}
