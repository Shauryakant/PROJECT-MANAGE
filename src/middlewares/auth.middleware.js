import { ApiError } from "../utils/api-error.js";
import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/asynchandlers.js";
import jwt from "jsonwebtoken";
import { Projectmember } from "../models/projectmember.model.js";
import mongoose, { mongo } from "mongoose";
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

export const validateProjectPermission = (roles = []) => {
  return asyncHandler(async (req, res, next) => {
    const { projectId } = req.params;
    if (!projectId) {
      throw new ApiError(400, "Please enter project id");
    }
    const member = await Projectmember.findOne({
      user: new mongoose.Types.ObjectId(req.user._id),
      project: new mongoose.Types.ObjectId(projectId),
    });
    if (!member) {
      throw new ApiError(404, "Project Member does not exist");
    }
    if (!roles.includes(member.role)) {
      throw new ApiError(404, "User not authorized to perform the operation");
    }
    req.user.role = member.role;
    next();
  });
};
