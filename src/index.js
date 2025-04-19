const express = require("express");
const cors = require("cors");
const path = require("path");
const mongodb = require("mongodb");

const PORT = process.env.PORT;
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(",");
const MODE = process.env.MODE;
const MONGODB_URI = process.env.MONGODB_URI;
const MONGODB_APPNAME = process.env.MONGODB_APPNAME;
const MONGODB_USERNAME = process.env.MONGODB_USERNAME;
const MONGODB_PASSWORD = process.env.MONGODB_PASSWORD;
const MONGODB_DATABASE = process.env.MONGODB_DATABASE;
const MONGODB_GAMES_COLLECTION = process.env.MONGODB_GAMES_COLLECTION;

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

const mongoClient = new mongodb.MongoClient(MONGODB_URI, {
  appName: MONGODB_APPNAME,
  auth: {
    username: MONGODB_USERNAME,
    password: MONGODB_PASSWORD,
  },
});
const app = express();
const gameRoute = express.Router();

if (MODE === "dev") {
  gameRoute.get("/dev/all", handleGetAllGames);
  gameRoute.post("/dev/new", handleInsertGame);
  gameRoute.delete("/dev/delete/:id", handleDeleteGame);
  gameRoute.patch("/dev/update/:id", handleUpdateGame);
}

app.use((req, _, next) => {
  console.log(req.method, req.path);
  next();
});
app.use(cors({ origin: ALLOWED_ORIGINS }));
app.use(express.static(path.join(__dirname, "..", "public")));
app.use(express.json());
app.use("/game", gameRoute);
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
    err === invalidCategoryError
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
      .findOne({}, { projection: { _id: false, id: true }, sort: { _id: -1 } });

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

function newGameId(prevIdx, category) {
  let idx = 1;
  if (prevIdx > 0) {
    idx = prevIdx + 1;
  }
  return "GAME" + categories.get(category) + idx.toString().padStart(4, "0");
}
