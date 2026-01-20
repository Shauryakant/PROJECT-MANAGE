import { ApiError } from "../utils/api-error.js";
import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/asynchandlers.js";
import jwt from "jsonwebtoken";
export const checkToken = asyncHandler(async (req, res, next) => {
  const token =
    req.cookies?.accessToken ||
    req.header("Authorization")?.replace("Bearer ", "");
  if (!token) {
    throw new ApiError(401, "Unauthorized access");
  }
  try {
    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET_KEY);
    const user = await User.findById(decodedToken._id).select(
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
    );
    if (!user) {
      throw new ApiError(401, "User not found");
    }
    req.user = user;
    next();
  } catch (error) {
    throw new ApiError(500, "JWT TOKEN VERIFICATION FAILED");
  }
});
