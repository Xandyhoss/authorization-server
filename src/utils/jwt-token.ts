import jwt from "jsonwebtoken";
import { Response } from "express";

import dotenv from "dotenv";
dotenv.config();

export class JWTTokenUtils {
  static generateJwtToken = (data: any) => {
    const jwtToken = jwt.sign(data, process.env.ACCESS_TOKEN_SECRET!, {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRATION || "15m",
    });
    return jwtToken;
  };

  static generateRefreshToken = (data: any) => {
    const refreshToken = jwt.sign(data, process.env.REFRESH_TOKEN_SECRET!, {
      expiresIn: process.env.REFRESH_TOKEN_EXPIRATION || "7d",
    });
    return refreshToken;
  };

  static setCookie = (tokenType: string, token: string, res: Response) => {
    res.cookie(tokenType, token, {
      domain: process.env.FRONTEND_DOMAIN || "localhost",
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
  };
}
