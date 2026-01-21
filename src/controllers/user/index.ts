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

  if (!login || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }

  const hashedPassword = EncryptionUtils.encryptData(password);

  const user = await db
    .select({
      id: usersTable.id,
      login: usersTable.login,
      user_metadata: usersTable.user_metadata,
    })
    .from(usersTable)
    .where(
      and(eq(usersTable.login, login), eq(usersTable.password, hashedPassword)),
    );

  if (!user[0]) {
    return res
      .status(404)
      .json({ message: "User not found or Invalid credentials" });
  }

  // Clear existing cookies for fresh session
  res.clearCookie("access_token");
  res.clearCookie("refresh_token");

  // Optionally clean up old refresh tokens for this user
  try {
    await db
      .delete(refreshTokensTable)
      .where(eq(refreshTokensTable.userId, user[0].id));
  } catch (error) {
    console.log("Error cleaning old refresh tokens: ", error);
  }

  // Generate new tokens
  const jwtToken = JWTTokenUtils.generateJwtToken(user[0]);
  const generatedRefreshToken = JWTTokenUtils.generateRefreshToken(user[0]);

  const refreshTokenData: typeof refreshTokensTable.$inferInsert = {
    refreshToken: EncryptionUtils.encryptData(generatedRefreshToken),
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
  const refreshToken = req.cookies.refresh_token;

  if (!refreshToken) {
    return res.status(400).json({ message: "Missing refresh token" });
  }

  try {
    await db
      .delete(refreshTokensTable)
      .where(
        eq(
          refreshTokensTable.refreshToken,
          EncryptionUtils.encryptData(refreshToken),
        ),
      );
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
  res: Response,
): Promise<any> => {
  const accessToken = req.cookies.access_token;
  if (!accessToken) {
    return res.status(401).json({ message: "Access token not found" });
  }

  try {
    const decoded = jwt.verify(
      accessToken,
      process.env.ACCESS_TOKEN_SECRET!,
    ) as any;
    return res.status(200).json({ user: decoded });
  } catch (error: any) {
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Access token expired" });
    } else if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "Invalid access token" });
    } else {
      console.log("Unexpected error in authenticate: ", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  }
};

export const refresh = async (req: Request, res: Response): Promise<any> => {
  const { refresh_token } = req.cookies;

  if (!refresh_token) {
    return res.status(401).json({ message: "Missing refresh token" });
  }

  try {
    // First verify the JWT token
    const decoded = jwt.verify(
      refresh_token,
      process.env.REFRESH_TOKEN_SECRET!,
    ) as any;

    // Then check if token exists in database
    const fetchedRefreshToken = await db
      .select()
      .from(refreshTokensTable)
      .where(
        eq(
          refreshTokensTable.refreshToken,
          EncryptionUtils.encryptData(refresh_token),
        ),
      );

    if (!fetchedRefreshToken[0]) {
      // Valid token but not in database - security issue
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      try {
        await db
          .delete(refreshTokensTable)
          .where(eq(refreshTokensTable.userId, decoded.id));
      } catch (cleanupError) {
        console.log("Error wiping refresh tokens: ", cleanupError);
      }
      return res.status(401).json({
        message: "Invalid refresh token session",
      });
    }

    // Get user data
    const user = await db
      .select({
        id: usersTable.id,
        login: usersTable.login,
        user_metadata: usersTable.user_metadata,
      })
      .from(usersTable)
      .where(eq(usersTable.id, decoded.id));

    if (!user[0]) {
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      return res.status(401).json({ message: "User not found" });
    }

    // Generate only new access token (refresh token still valid)
    const jwtToken = JWTTokenUtils.generateJwtToken(user[0]);
    JWTTokenUtils.setCookie("access_token", jwtToken, res);

    return res.status(200).json({
      user: user[0],
      token: {
        accessToken: jwtToken,
        refreshToken: refresh_token,
      },
    });
  } catch (error: any) {
    if (error.name === "TokenExpiredError") {
      // Refresh token rotation: generate new tokens even if expired
      let decodedRefreshToken;
      try {
        decodedRefreshToken = jwt.decode(refresh_token) as any;
      } catch (decodeError) {
        res.clearCookie("access_token");
        res.clearCookie("refresh_token");
        return res
          .status(401)
          .json({ message: "Invalid refresh token format" });
      }

      if (!decodedRefreshToken || !decodedRefreshToken.id) {
        res.clearCookie("access_token");
        res.clearCookie("refresh_token");
        return res
          .status(401)
          .json({ message: "Invalid refresh token payload" });
      }

      // Check if expired token exists in database
      const fetchedRefreshToken = await db
        .select()
        .from(refreshTokensTable)
        .where(
          eq(
            refreshTokensTable.refreshToken,
            EncryptionUtils.encryptData(refresh_token),
          ),
        );

      if (!fetchedRefreshToken[0]) {
        // Expired token not in database - security issue
        res.clearCookie("access_token");
        res.clearCookie("refresh_token");
        try {
          await db
            .delete(refreshTokensTable)
            .where(eq(refreshTokensTable.userId, decodedRefreshToken.id));
        } catch (cleanupError) {
          console.log("Error wiping refresh tokens: ", cleanupError);
        }
        return res.status(401).json({
          message: "Invalid refresh token session",
        });
      }

      // Get user data for new tokens
      const user = await db
        .select({
          id: usersTable.id,
          login: usersTable.login,
          user_metadata: usersTable.user_metadata,
        })
        .from(usersTable)
        .where(eq(usersTable.id, decodedRefreshToken.id));

      if (!user[0]) {
        res.clearCookie("access_token");
        res.clearCookie("refresh_token");
        return res.status(401).json({ message: "User not found" });
      }

      // Generate new tokens (rotation)
      const jwtToken = JWTTokenUtils.generateJwtToken(user[0]);
      const generatedRefreshToken = JWTTokenUtils.generateRefreshToken(user[0]);

      const refreshTokenData: typeof refreshTokensTable.$inferInsert = {
        refreshToken: EncryptionUtils.encryptData(generatedRefreshToken),
        userId: user[0].id,
      };

      // Use transaction for atomic token replacement
      try {
        await db.transaction(async (tx) => {
          // Replace old refresh token with new one atomically
          await tx
            .delete(refreshTokensTable)
            .where(
              eq(
                refreshTokensTable.refreshToken,
                EncryptionUtils.encryptData(refresh_token),
              ),
            );

          await tx.insert(refreshTokensTable).values(refreshTokenData);
        });

        JWTTokenUtils.setCookie("access_token", jwtToken, res);
        JWTTokenUtils.setCookie("refresh_token", generatedRefreshToken, res);

        return res.status(200).json({
          user: user[0],
          token: {
            accessToken: jwtToken,
            refreshToken: generatedRefreshToken,
          },
        });
      } catch (dbError) {
        console.log("Error rotating refresh token: ", dbError);
        res.clearCookie("access_token");
        res.clearCookie("refresh_token");
        return res
          .status(500)
          .json({ message: "Error rotating refresh token" });
      }
    } else if (error.name === "JsonWebTokenError") {
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      return res.status(401).json({ message: "Invalid refresh token" });
    } else {
      console.log("Unexpected error in refresh: ", error);
      res.clearCookie("access_token");
      res.clearCookie("refresh_token");
      return res.status(500).json({ message: "Internal server error" });
    }
  }
};
