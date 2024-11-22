import crypto from "crypto";

export class EncryptionUtils {
  public static encryptData(data: string) {
    return crypto.createHash("sha256").update(data).digest("hex");
  }
}
