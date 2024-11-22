import express, { Request, Response } from "express";
import dotenv from "dotenv";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import {
  authenticate,
  createUser,
  deleteUser,
  listUsers,
  login,
  logout,
  refresh,
} from "./controllers/user";

dotenv.config();

const app = express();
const PORT = process.env.HOST_PORT || 3000;

app.use(bodyParser.json());
app.use(cookieParser());

app.get("/", (_req: Request, res: Response) => {
  res.json({
    message: `Server is running OK: ${new Date().toISOString()}`,
  });
});

app.get("/users", listUsers);

app.post("/user/login", login);

app.get("/user/logout", logout);

app.post("/user/create", createUser);

app.delete("/user/delete/:id", deleteUser);

app.get("/authenticate", authenticate);

app.get("/refresh", refresh);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
