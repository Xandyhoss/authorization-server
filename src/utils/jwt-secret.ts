import crypto from "crypto";
import dotenv from "dotenv";
import path from "path";
import fs from "fs";

const generateSecret = () => {
  return crypto.randomBytes(32).toString("hex");
};

dotenv.config();

const envFilePath = path.resolve(__dirname, "../../.env");

const writeEnvKey = async (key: string, value: string) => {
  try {
    const data = await fs.promises.readFile(envFilePath, "utf8");

    const regex = new RegExp(`^${key}=.*`, "m");
    const newEnvData = regex.test(data)
      ? data.replace(regex, `${key}=${value}`)
      : data + `\n${key}=${value}`;

    await fs.promises.writeFile(envFilePath, newEnvData, "utf8");

    console.log(`${key} has been updated successfully.`);
  } catch (err) {
    console.error("Error handling .env file:", err);
  }
};

const ACCESS_TOKEN_SECRET = generateSecret();
const REFRESH_TOKEN_SECRET = generateSecret();

(async () => {
  await writeEnvKey('ACCESS_TOKEN_SECRET', `'${ACCESS_TOKEN_SECRET}'`);
  await writeEnvKey('REFRESH_TOKEN_SECRET', `'${REFRESH_TOKEN_SECRET}'`);
})();
