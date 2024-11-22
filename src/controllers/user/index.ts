import { and, eq } from "drizzle-orm";
import db from "../../db";
import { refreshTokensTable, usersTable } from "../../db/schema";
import { Request, Response } from "express";
import { EncryptionUtils } from "../../utils/encryption";
import jwt from "jsonwebtoken";
import { JWTTokenUtils } from "../../utils/jwt-token";

export const listUsers = async (_req: Request, res: Response): Promise<any> => {
  try {
    const data = await db.select().from(usersTable);
    return res.status(200).json(data);
  } catch (error) {
    console.log("Error fetching users: ", error);
    return res.status(500).json({ message: "Error fetching users" });
  }
};

export const login = async (req: Request, res: Response): Promise<any> => {
  const { login, password } = req.body;
  const { refresh_token } = req.cookies;

  if (!login || !password) {
    return res.status(500).json({ message: "Missing required fields" });
  }

  const hashedPassword = EncryptionUtils.encryptData(password);

  const user = await db
    .select({
      id: usersTable.id,
      login: usersTable.login,
      userData: usersTable.user_metadata,
    })
    .from(usersTable)
    .where(
      and(eq(usersTable.login, login), eq(usersTable.password, hashedPassword))
    );

  if (!user[0]) {
    return res
      .status(404)
      .json({ message: "User not found or Invalid credentials" });
  }

  if (refresh_token) {
    const fetchedRefreshToken = await db
      .select()
      .from(refreshTokensTable)
      .where(
        and(
          eq(refreshTokensTable.userId, user[0].id),
          eq(refreshTokensTable.refreshToken, refresh_token)
        )
      );
    if (fetchedRefreshToken[0]) {
      try {
        await db
          .delete(refreshTokensTable)
          .where(eq(refreshTokensTable.refreshToken, refresh_token));
      } catch (error) {
        console.log("Error excluding refresh token: ", error);
        res.status(500).json({ message: "Error excluding old refresh token" });
      }
    }
  }

  const jwtToken = JWTTokenUtils.generateJwtToken(user[0]);
  const generatedRefreshToken = JWTTokenUtils.generateRefreshToken(user[0]);

  const refreshTokenData: typeof refreshTokensTable.$inferInsert = {
    refreshToken: generatedRefreshToken,
    userId: user[0].id,
  };

  try {
    await db.insert(refreshTokensTable).values(refreshTokenData);

    JWTTokenUtils.setCookie("access_token", jwtToken, res);
    JWTTokenUtils.setCookie("refresh_token", generatedRefreshToken, res);

    return res.status(200).json({
      user: user[0],
      token: {
        accessToken: jwtToken,
        refreshToken: generatedRefreshToken,
      },
    });
  } catch (error) {
    console.log("Error inserting refresh token into db: ", error);
    res.status(500).json({ message: "Error inserting refresh token into db" });
  }
};

export const logout = async (req: Request, res: Response): Promise<any> => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(400).json({ message: "Missing refresh token" });
  }

  try {
    await db
      .delete(refreshTokensTable)
      .where(eq(refreshTokensTable.refreshToken, refreshToken));
  } catch (error) {
    console.log("Error excluding refresh token: ", error);
    return res
      .status(500)
      .json({ message: "Error excluding old refresh token" });
  }

  res.clearCookie("access_token");
  res.clearCookie("refresh_token");
  return res.status(200).json({ message: "Logged out" });
};

export const createUser = async (req: Request, res: Response): Promise<any> => {
  const { login, password, user_metadata } = req.body;

  if (!login || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const user: typeof usersTable.$inferInsert = {
    login,
    password: EncryptionUtils.encryptData(password),
    user_metadata,
  };

  try {
    const data = await db.insert(usersTable).values(user).returning();
    return res.status(200).json({ user: data[0] });
  } catch (error) {
    console.log("Error creating user: ", error);
    return res.status(500).json({ message: "Error creating user" });
  }
};

export const deleteUser = async (req: Request, res: Response): Promise<any> => {
  const { id } = req.params;

  if (!id) {
    return res.status(500).json({ message: "Missing user ID" });
  }

  try {
    await db.delete(usersTable).where(eq(usersTable.id, id as string));
    return res.status(200).json({ message: "User deleted" });
  } catch (error) {
    console.log("Error deleting user: ", error);
    return res.status(500).json({ message: "Error deleting user" });
  }
};

export const authenticate = async (
  req: Request,
  res: Response
): Promise<any> => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }

  jwt.verify(
    accessToken,
    process.env.ACCESS_TOKEN_SECRET!,
    (err: any, decoded: any) => {
      if (err) return res.status(403).json({ message: "Invalid access token" });

      return res.status(200).json({ user: decoded });
    }
  );
};

export const refresh = async (req: Request, res: Response): Promise<any> => {
  const { refresh_token } = req.cookies;

  if (!refresh_token) {
    return res.status(400).json({ message: "Missing refresh token" });
  }

  jwt.verify(
    refresh_token,
    process.env.REFRESH_TOKEN_SECRET!,
    async (err: any, decoded: any) => {
      const fetchedRefreshToken = await db
        .select()
        .from(refreshTokensTable)
        .where(and(eq(refreshTokensTable.refreshToken, refresh_token)));

      if (err) {
        if (err.name === "TokenExpiredError") {
          const decodedRefreshToken = jwt.decode(refresh_token) as any;
          if (!fetchedRefreshToken[0]) {
            try {
              await db
                .delete(refreshTokensTable)
                .where(eq(refreshTokensTable.userId, decodedRefreshToken?.id!));
              res.clearCookie("access_token");
              res.clearCookie("refresh_token");
              return res.status(500).json({
                message:
                  "This refresh token is valid but don't exists in the database. Wiping all refresh token due security reasons",
              });
            } catch (error) {
              console.log("Error wiping refresh tokens: ", error);
              return res
                .status(500)
                .json({ message: "Error wiping refresh tokens" });
            }
          }

          const user = await db
            .select({
              id: usersTable.id,
              login: usersTable.login,
              userData: usersTable.user_metadata,
            })
            .from(usersTable)
            .where(eq(usersTable.id, decodedRefreshToken.id));

          const jwtToken = JWTTokenUtils.generateJwtToken(user[0]);
          const generatedRefreshToken = JWTTokenUtils.generateRefreshToken(
            user[0]
          );

          const refreshTokenData: typeof refreshTokensTable.$inferInsert = {
            refreshToken: generatedRefreshToken,
            userId: user[0].id,
          };

          try {
            await db
              .delete(refreshTokensTable)
              .where(eq(refreshTokensTable.refreshToken, refresh_token));

            await db.insert(refreshTokensTable).values(refreshTokenData);

            JWTTokenUtils.setCookie("access_token", jwtToken, res);
            JWTTokenUtils.setCookie(
              "refresh_token",
              generatedRefreshToken,
              res
            );

            return res.status(200).json({
              user: user[0],
              token: {
                accessToken: jwtToken,
                refreshToken: generatedRefreshToken,
              },
            });
          } catch (error) {
            console.log("Error inserting refresh token into db: ", error);
            return res
              .status(500)
              .json({ message: "Error inserting refresh token into db" });
          }
        } else if (err.name === "JsonWebTokenError") {
          return res.status(403).json({ message: "Invalid refresh token" });
        }
      }

      const decodedRefreshToken = decoded;

      if (!fetchedRefreshToken[0]) {
        try {
          await db
            .delete(refreshTokensTable)
            .where(eq(refreshTokensTable.userId, decodedRefreshToken.id));
          res.clearCookie("access_token");
          res.clearCookie("refresh_token");
          return res.status(500).json({
            message:
              "This refresh token is valid but don't exists in the database. Wiping all refresh token due security reasons",
          });
        } catch (error) {
          console.log("Error wiping refresh tokens: ", error);
          res.status(500).json({ message: "Error wiping refresh tokens" });
        }
      }

      const user = await db
        .select({
          id: usersTable.id,
          login: usersTable.login,
          userData: usersTable.user_metadata,
        })
        .from(usersTable)
        .where(eq(usersTable.id, decodedRefreshToken.id));

      const jwtToken = JWTTokenUtils.generateJwtToken(user[0]);

      JWTTokenUtils.setCookie("access_token", jwtToken, res);

      return res.status(200).json({
        user: user[0],
        token: {
          accessToken: jwtToken,
        },
      });
    }
  );
};
